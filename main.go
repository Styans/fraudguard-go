package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	openai "github.com/sashabaranov/go-openai"
)

type TGUpdate struct {
	Message *struct {
		MessageID int    `json:"message_id"`
		Text      string `json:"text"`
		Chat      struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Voice *struct {
			FileID string `json:"file_id"`
		} `json:"voice"`
	} `json:"message"`
}

type RiskResult struct {
	Risk           int      `json:"risk"`
	Reasons        []string `json:"reasons"`
	Recommendation string   `json:"recommendation"`
	Level          string   `json:"level"`
}

func main() {
	_ = godotenv.Load()

	tgToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if tgToken == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN is empty")
	}
	openaiKey := os.Getenv("OPENAI_API_KEY")
	if openaiKey == "" {
		log.Fatal("OPENAI_API_KEY is empty")
	}
	baseURL := os.Getenv("OPENAI_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	cfg := openai.DefaultConfig(openaiKey)
	cfg.BaseURL = baseURL
	oc := openai.NewClientWithConfig(cfg)

	app := fiber.New()

	// Telegram webhook endpoint
	app.Post("/webhook", func(c *fiber.Ctx) error {
		var upd TGUpdate
		if err := c.BodyParser(&upd); err != nil {
			return c.SendStatus(200)
		}
		if upd.Message == nil {
			return c.SendStatus(200)
		}
		chatID := upd.Message.Chat.ID

		switch {
		case upd.Message.Text != "":
			text := upd.Message.Text
			res := analyzeText(c.Context(), oc, text)
			sendResultToTG(tgToken, chatID, text, res)
		case upd.Message.Voice != nil:
			text, err := transcribeVoice(tgToken, upd.Message.Voice.FileID, oc)
			if err != nil || strings.TrimSpace(text) == "" {
				sendTG(tgToken, chatID, "Не удалось распознать голосовое. Пришлите текст или другое аудио.")
				return c.SendStatus(200)
			}
			res := analyzeText(c.Context(), oc, text)
			sendResultToTG(tgToken, chatID, text, res)
		default:
			sendTG(tgToken, chatID, "Пришлите текст или голосовое сообщение для проверки.")
		}
		return c.SendStatus(200)
	})

	log.Println("FraudGuard AI listening on :8000")
	log.Fatal(app.Listen(":8000"))
}

// ---------- AI: анализ текста (gpt-4o-mini) ----------
func analyzeText(ctx context.Context, oc *openai.Client, text string) RiskResult {
	prompt := `
Ты эксперт по кибербезопасности. Проанализируй сообщение на признаки онлайн-мошенничества (фишинг, социнжиниринг, давление).
Оцени риск 0-100 (чем выше, тем опаснее). Верни СТРОГО валидный JSON:
{
 "risk": <0-100>,
 "level": "<low|medium|high>",
 "reasons": ["...","..."],
 "recommendation": "..."
}
Повышай риск при наличии: срочности/давления/угроз/перевода денег/"код из SMS"/лжебанка/подозрительных ссылок.
Сообщение: """` + text + `"""`
	req := openai.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "Отвечай только валидным JSON без пояснений."},
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
		Temperature: 0.1,
	}

	resp, err := oc.CreateChatCompletion(ctx, req)
	if err != nil || len(resp.Choices) == 0 {
		return RiskResult{Risk: 50, Level: "medium", Reasons: []string{"Ошибка анализа"}, Recommendation: "Перепроверьте источник сообщения."}
	}

	var out RiskResult
	if err := json.Unmarshal([]byte(resp.Choices[0].Message.Content), &out); err != nil {
		out = RiskResult{Risk: 60, Level: "medium", Reasons: []string{"Нестрогий формат ответа ИИ"}, Recommendation: "Будьте осторожны."}
	}
	// нормализуем поля
	if out.Risk < 0 { out.Risk = 0 }
	if out.Risk > 100 { out.Risk = 100 }
	if out.Level == "" {
		switch {
		case out.Risk >= 80:
			out.Level = "high"
		case out.Risk >= 40:
			out.Level = "medium"
		default:
			out.Level = "low"
		}
	}
	return out
}

// ---------- AI: распознавание голосового (Whisper-1) ----------
func transcribeVoice(tgToken, fileID string, oc *openai.Client) (string, error) {
	// 1) Получаем file_path у Telegram
	fileInfoURL := fmt.Sprintf("https://api.telegram.org/bot%s/getFile?file_id=%s", tgToken, fileID)
	resp, err := http.Get(fileInfoURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var f struct {
		OK     bool `json:"ok"`
		Result struct {
			FilePath string `json:"file_path"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil || !f.OK {
		return "", fmt.Errorf("tg getFile failed")
	}

	// 2) Скачиваем файл
	fileURL := fmt.Sprintf("https://api.telegram.org/file/bot%s/%s", tgToken, f.Result.FilePath)
	audioResp, err := http.Get(fileURL)
	if err != nil {
		return "", err
	}
	defer audioResp.Body.Close()

	tmp := "voice.ogg"
	out, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	defer func() {
		out.Close()
		os.Remove(tmp)
	}()
	if _, err := io.Copy(out, audioResp.Body); err != nil {
		return "", err
	}

	// 3) Whisper transcription
	tr := openai.AudioRequest{
		Model:    "whisper-1",
		FilePath: tmp,
	}
	tres, err := oc.CreateTranscription(context.Background(), tr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(tres.Text), nil
}

// ---------- Telegram отправка ----------
func sendResultToTG(tgToken string, chatID int64, original string, r RiskResult) {
	bar := riskBar(r.Risk)
	reasons := "-"
	if len(r.Reasons) > 0 {
		reasons = "- " + strings.Join(r.Reasons, "\n- ")
	}
	msg := fmt.Sprintf(
		"🛡️ *FraudGuard AI*\n\n*Оригинал:*\n`%s`\n\n*Риск:* %d%% %s\n*Уровень:* %s\n*Причины:*\n%s\n\n*Совет:* %s",
		truncate(original, 800), r.Risk, bar, strings.ToUpper(r.Level), reasons, r.Recommendation,
	)
	sendTG(tgToken, chatID, msg)
}

func riskBar(r int) string {
	if r < 0 { r = 0 }
	if r > 100 { r = 100 }
	blocks := r / 10
	full := strings.Repeat("█", blocks)
	empty := strings.Repeat("░", 10-blocks)
	return "│" + full + empty + "│"
}

func truncate(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n] + "…"
}

func sendTG(token string, chatID int64, text string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]string{
		"chat_id":    strconv.FormatInt(chatID, 10),
		"text":       text,
		"parse_mode": "Markdown",
	}
	b, _ := json.Marshal(payload)
	http.Post(url, "application/json", bytes.NewReader(b))
}
