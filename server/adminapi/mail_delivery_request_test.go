package adminapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"reflect"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

// formPart is one part of a multipart/form-data test body.
type formPart struct {
	name, filename, value string
	header                textproto.MIMEHeader // overrides name and filename when set
}

func buildForm(t testing.TB, parts ...formPart) (contentType string, body []byte) {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for _, p := range parts {
		var w io.Writer
		var err error
		switch {
		case p.header != nil:
			w, err = mw.CreatePart(p.header)
		case p.filename != "":
			w, err = mw.CreateFormFile(p.name, p.filename)
		default:
			w, err = mw.CreateFormField(p.name)
		}
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, p.value)
	}
	mw.Close()
	return mw.FormDataContentType(), b.Bytes()
}

func formRequest(contentType string, body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/admin/mail/deliver", bytes.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	return r
}

// parseFormAsBefore is how the handler read a multipart request through
// http.Request.ParseMultipartForm before #2120.
func parseFormAsBefore(t testing.TB, contentType string, body []byte) (DeliverMailRequest, []byte, bool) {
	t.Helper()
	var req DeliverMailRequest
	r := formRequest(contentType, body)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return req, nil, false
	}
	var message []byte
	if len(r.MultipartForm.Value["message"]) > 0 {
		message = []byte(r.MultipartForm.Value["message"][0])
	} else if len(r.MultipartForm.File["message"]) > 0 {
		f, err := r.MultipartForm.File["message"][0].Open()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if message, err = io.ReadAll(f); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.MultipartForm.Value["recipients"]) > 0 {
		req.Recipients = r.MultipartForm.Value["recipients"]
	}
	if len(r.MultipartForm.Value["from"]) > 0 {
		req.From = r.MultipartForm.Value["from"][0]
	}
	return req, message, true
}

// The streaming multipart reader takes from a form what ParseMultipartForm gave the
// handler: the message as a form value or a file wherever it is in the body, the
// value before the file, the first of each, every recipients value, the first from.
func TestDeliverMailMultipartMatchesParseMultipartForm(t *testing.T) {
	value := formPart{name: "message", value: "From: a@example.com\r\n\r\nthe form value\r\n"}
	file := formPart{name: "message", filename: "m.eml", value: "From: a@example.com\r\n\r\nthe file\r\n"}
	otherValue := formPart{name: "message", value: "From: a@example.com\r\n\r\nsecond value\r\n"}
	otherFile := formPart{name: "message", filename: "n.eml", value: "From: a@example.com\r\n\r\nsecond file\r\n"}
	rcpt1 := formPart{name: "recipients", value: "one@example.com"}
	rcpt2 := formPart{name: "recipients", value: " two@example.com "}
	from1 := formPart{name: "from", value: "sender@example.com"}
	from2 := formPart{name: "from", value: "other@example.com"}
	unknown := formPart{name: "attachment", filename: "big.bin", value: strings.Repeat("x", 100<<10)}
	unknownValue := formPart{name: "note", value: "ignored"}
	recipientsFile := formPart{name: "recipients", filename: "r.txt", value: "file@example.com"}
	noName := formPart{header: textproto.MIMEHeader{"Content-Disposition": {`form-data; filename="x"`}}, value: "no name"}
	emptyFilename := formPart{header: textproto.MIMEHeader{"Content-Disposition": {`form-data; name="message"; filename=""`}}, value: "From: a@example.com\r\n\r\nempty filename is a value\r\n"}
	quotedPrintable := formPart{header: textproto.MIMEHeader{
		"Content-Disposition":       {`form-data; name="message"`},
		"Content-Transfer-Encoding": {"quoted-printable"},
	}, value: "From: a@example.com\r\n\r\nsoft=\r\nbreak =41\r\n"}
	emptyValue := formPart{name: "message", value: ""}

	for name, parts := range map[string][]formPart{
		"value last":                    {rcpt1, from1, value},
		"value first":                   {value, rcpt1, from1},
		"file last":                     {rcpt1, from1, file},
		"file first":                    {file, rcpt1, from1},
		"value then file":               {value, file, rcpt1},
		"file then value":               {file, rcpt1, value},
		"two values":                    {value, otherValue, rcpt1},
		"two files":                     {file, otherFile, rcpt1},
		"file, file, value, value":      {file, otherFile, value, otherValue},
		"several recipients and froms":  {rcpt1, value, rcpt2, from1, from2},
		"unknown parts":                 {unknown, rcpt1, unknownValue, value, unknown, noName},
		"recipients as a file":          {recipientsFile, value},
		"no message":                    {rcpt1, from1},
		"no parts":                      {},
		"empty filename":                {emptyFilename, rcpt1},
		"empty value before a file":     {emptyValue, file},
		"empty file":                    {{name: "message", filename: "empty.eml"}, rcpt1},
		"quoted-printable message part": {quotedPrintable, rcpt1},
	} {
		t.Run(name, func(t *testing.T) {
			contentType, body := buildForm(t, parts...)
			wantReq, wantMessage, ok := parseFormAsBefore(t, contentType, body)
			if !ok {
				t.Fatal("ParseMultipartForm refused the fixture")
			}
			budget := server.NewSessionMemoryTracker(0)
			d := &deliverMailReader{budget: budget}
			req, message, err := d.multipart(formRequest(contentType, body))
			if err != nil {
				t.Fatalf("multipart: %v", err)
			}
			if string(message) != string(wantMessage) {
				t.Errorf("message %q, ParseMultipartForm gave %q", message, wantMessage)
			}
			if !reflect.DeepEqual(req, wantReq) {
				t.Errorf("request %+v, ParseMultipartForm gave %+v", req, wantReq)
			}
			// A part that is not the message is never read into memory, and a message
			// that lost is not kept: what stays charged is one message buffer and the
			// small fields.
			if d.held != budget.Current() {
				t.Errorf("reader holds %d, budget %d", d.held, budget.Current())
			}
			if max := int64(64<<10 + 4096); d.held > max {
				t.Errorf("%d bytes still charged after the form was read, want at most one message buffer (%d)", d.held, max)
			}
			if total, max := budget.TotalAllocated(), int64(4*32<<10+4096); total > max {
				t.Errorf("%d bytes charged in all for a form whose message parts are small, want at most %d: a skipped part was read", total, max)
			}
			d.release()
			if budget.Current() != 0 {
				t.Errorf("%d bytes charged after release", budget.Current())
			}
		})
	}
}

// What the multipart reader refuses, and how.
func TestDeliverMailMultipartRefusals(t *testing.T) {
	message := formPart{name: "message", value: "From: a@example.com\r\n\r\nbody\r\n"}
	contentType, body := buildForm(t, formPart{name: "recipients", value: "one@example.com"}, message)

	malformed := func(t *testing.T, contentType string, body []byte) {
		t.Helper()
		d := &deliverMailReader{budget: server.NewSessionMemoryTracker(0)}
		_, msg, err := d.multipart(formRequest(contentType, body))
		var bad deliverRequestError
		if !errors.As(err, &bad) || string(bad) != "Failed to parse multipart form" || msg != nil {
			t.Fatalf("err = %v, message %q; want the malformed-form refusal and no message", err, msg)
		}
		if _, _, ok := parseFormAsBefore(t, contentType, body); ok {
			t.Fatal("ParseMultipartForm accepted this form")
		}
	}
	t.Run("no boundary", func(t *testing.T) { malformed(t, "multipart/form-data", body) })
	t.Run("truncated in the message", func(t *testing.T) { malformed(t, contentType, body[:len(body)-60]) })
	t.Run("truncated in a small field", func(t *testing.T) {
		i := bytes.Index(body, []byte("one@example.com"))
		malformed(t, contentType, body[:i+5])
	})
	t.Run("no closing boundary", func(t *testing.T) {
		malformed(t, contentType, bytes.TrimSuffix(bytes.TrimSpace(body), []byte("--")))
	})
	t.Run("more parts than ParseMultipartForm takes", func(t *testing.T) {
		parts := make([]formPart, maxDeliverFormParts+1)
		for i := range parts {
			parts[i] = formPart{name: "x", value: "y"}
		}
		contentType, body := buildForm(t, parts...)
		malformed(t, contentType, body)
	})
	t.Run("as many parts as ParseMultipartForm takes", func(t *testing.T) {
		parts := make([]formPart, maxDeliverFormParts)
		for i := range parts {
			parts[i] = formPart{name: "x", value: "y"}
		}
		parts[len(parts)-1] = message
		contentType, body := buildForm(t, parts...)
		d := &deliverMailReader{}
		if _, msg, err := d.multipart(formRequest(contentType, body)); err != nil || string(msg) != message.value {
			t.Fatalf("message %q, err %v", msg, err)
		}
		if _, _, ok := parseFormAsBefore(t, contentType, body); !ok {
			t.Fatal("ParseMultipartForm refused this form")
		}
	})

	for _, field := range []string{"recipients", "from"} {
		t.Run(field+" at the field limit", func(t *testing.T) {
			contentType, body := buildForm(t, formPart{name: field, value: strings.Repeat("a", maxDeliverFormField)}, message)
			d := &deliverMailReader{}
			req, _, err := d.multipart(formRequest(contentType, body))
			if err != nil || len(req.From)+len(strings.Join(req.Recipients, "")) != maxDeliverFormField {
				t.Fatalf("err %v, request %d bytes", err, len(req.From)+len(strings.Join(req.Recipients, "")))
			}
		})
		t.Run(field+" over the field limit", func(t *testing.T) {
			contentType, body := buildForm(t, formPart{name: field, value: strings.Repeat("a", maxDeliverFormField+1)}, message)
			d := &deliverMailReader{}
			_, _, err := d.multipart(formRequest(contentType, body))
			var bad deliverRequestError
			if !errors.As(err, &bad) || !strings.Contains(string(bad), field) {
				t.Fatalf("err = %v; want a refusal naming %s", err, field)
			}
		})
	}

	t.Run("message over the budget", func(t *testing.T) {
		for _, filename := range []string{"", "m.eml"} {
			contentType, body := buildForm(t, formPart{name: "message", filename: filename, value: strings.Repeat("x", 100<<10)})
			budget := server.NewSessionMemoryTracker(64 << 10)
			d := &deliverMailReader{budget: budget}
			_, _, err := d.multipart(formRequest(contentType, body))
			if !errors.Is(err, server.ErrMemoryBudgetExhausted) {
				t.Fatalf("filename %q: err = %v, want the budget refusal", filename, err)
			}
			d.release()
			if budget.Current() != 0 {
				t.Fatalf("filename %q: %d bytes charged after release", filename, budget.Current())
			}
		}
	})
	t.Run("skipped part needs no budget", func(t *testing.T) {
		contentType, body := buildForm(t, formPart{name: "attachment", filename: "big.bin", value: strings.Repeat("x", 1<<20)}, message)
		d := &deliverMailReader{budget: server.NewSessionMemoryTracker(40 << 10)}
		if _, msg, err := d.multipart(formRequest(contentType, body)); err != nil || string(msg) != message.value {
			t.Fatalf("message %q, err %v", msg, err)
		}
	})
}

// decodeJSONAsBefore is how the handler decoded a JSON request before #2120.
func decodeJSONAsBefore(body []byte) (DeliverMailRequest, error) {
	var req DeliverMailRequest
	err := json.NewDecoder(bytes.NewReader(body)).Decode(&req)
	return req, err
}

// checkJSONMatchesDecoder decodes body with the charged JSON reader and with
// json.Decoder into DeliverMailRequest, and requires the same outcome: both refuse
// it, or both give the same message, byte for byte, and the same other fields.
func checkJSONMatchesDecoder(t testing.TB, body []byte) {
	t.Helper()
	want, wantErr := decodeJSONAsBefore(body)
	budget := server.NewSessionMemoryTracker(0)
	d := &deliverMailReader{budget: budget}
	req, message, err := d.json(bytes.NewReader(body))
	if (err == nil) != (wantErr == nil) {
		t.Fatalf("body %q: err = %v, json.Decoder: %v", body, err, wantErr)
	}
	if err != nil {
		var bad deliverRequestError
		if !errors.As(err, &bad) || string(bad) != "Invalid JSON" {
			t.Fatalf("body %q: err = %v, want the Invalid JSON refusal", body, err)
		}
		return
	}
	if string(message) != want.Message {
		t.Fatalf("body %q: message %q, json.Decoder %q", body, message, want.Message)
	}
	if req.Message != "" {
		t.Fatalf("body %q: the message was also decoded into a string", body)
	}
	want.Message = ""
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("body %q: request %+v, json.Decoder %+v", body, req, want)
	}
	// The body's buffer is freed; what stays charged is exactly the message.
	if d.held != budget.Current() || d.held != int64(len(message)) || cap(message) != len(message) {
		t.Fatalf("body %q: %d bytes held (budget %d) for a %d-byte message in a %d-byte buffer", body, d.held, budget.Current(), len(message), cap(message))
	}
}

var jsonMessageSeeds = []string{
	`{"message":"From: a@example.com\r\n\r\nbody\r\n","recipients":["one@example.com","two@example.com"],"from":"s@example.com"}`,
	`{"recipients":["one@example.com"],"message":"m","uid":7,"uid_validity":9,"mailbox":"Archive"}`,
	`{"message":"quote \" backslash \\ slash \/ and \b\f\n\r\t"}`,
	`{"message":"Aé日 😀 😀"}`,
	`{"message":"ünïcödé 日本語 😀"}`,
	`{"message":"lone high \ud800 x"}`,
	`{"message":"lone low \udc00 x"}`,
	`{"message":"high then non-low \ud800A"}`,
	`{"message":"high then high \ud800𐀀"}`,
	`{"message":"high at the end \ud83d"}`,
	`{"message":"high then a plain escape \ud83d\n"}`,
	"{\"message\":\"invalid utf-8 \xff\xfe \xc3 \xe2\x82 \xf0\x9f\x98 end\"}",
	"{\"message\":\"\xed\xa0\x80 encoded surrogate, \xc0\x80 overlong\"}",
	`{"message":""}`,
	`{"message":null}`,
	`{"message":"first","message":"second"}`,
	`{"message":"first","message":null}`,
	`{"message":"first","MESSAGE":"folded key"}`,
	`{"Message":"folded key"}`,
	`{"message":"m","unknown":{"message":"nested","a":[1,2,{"b":"}"}]},"x":"\"}"}`,
	`{"message":"m"} trailing garbage`,
	`{"message":"m"}{"message":"second value"}`,
	`{"message":"m"}}`,
	"  \r\n\t{\"message\":\"leading space\"}\n",
	`null`,
	`null trailing`,
	` null`,
	`nullx`,
	`{}`,
	``,
	`   `,
	`{"message":42}`,
	`{"message":["a"]}`,
	`{"message":{"a":1}}`,
	`{"message":true}`,
	`{"message":"m","recipients":"not a list"}`,
	`{"message":"m","uid":-1}`,
	`{"message":"unterminated`,
	`{"message":"bad escape \x"}`,
	`{"message":"bad unicode \u12G4"}`,
	"{\"message\":\"raw control \x01\"}",
	"{\"message\":\"raw newline \n\"}",
	`{"message":"m",}`,
	`{"message" "m"}`,
	`["message","m"]`,
	`"message"`,
	`5`,
	`{"message":"m"`,
	`{"a":"\"}","message":"brace in a string"}`,
	`{"a":"\\","message":"backslash before the quote"}`,
}

// The charged JSON reader decodes a request as json.Decoder did.
func TestJSONMessageMatchesEncodingJSON(t *testing.T) {
	for _, body := range jsonMessageSeeds {
		checkJSONMatchesDecoder(t, []byte(body))
	}
	// Every single byte, every two-byte sequence around the surrogates and every
	// escape, as raw string content: what is valid must decode alike, what is not
	// must be refused alike.
	for b := range 256 {
		checkJSONMatchesDecoder(t, []byte(`{"message":"a`+string([]byte{byte(b)})+`z"}`))
		checkJSONMatchesDecoder(t, []byte(`{"message":"a\`+string([]byte{byte(b)})+`z"}`))
		checkJSONMatchesDecoder(t, []byte(`{"message":"`+string([]byte{0xed, byte(b)})+`\ud83d`+string([]byte{byte(b)})+`"}`))
	}
	for _, hi := range []int{0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0xfffd, 0xffff, 0} {
		for _, lo := range []int{0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0x41} {
			checkJSONMatchesDecoder(t, []byte(fmt.Sprintf(`{"message":"\u%04x\u%04X|\u%04x"}`, hi, lo, hi)))
		}
	}
	// A message as encoding/json writes it.
	message := "From: a@example.com\r\nSubject: \"q\" \\ / \t <>&  \r\n\r\n" + strings.Repeat("line ünï 😀\r\n", 2000) + "\x00\x1f\x7f"
	body, err := json.Marshal(DeliverMailRequest{Message: message, Recipients: []string{"one@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	checkJSONMatchesDecoder(t, body)
}

// FuzzJSONMessage holds the charged JSON reader to json.Decoder's result for any
// request body, and for any bytes as the content of the message string.
func FuzzJSONMessage(f *testing.F) {
	for _, seed := range jsonMessageSeeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		checkJSONMatchesDecoder(t, data)
		checkJSONMatchesDecoder(t, append(append([]byte(`{"message":"`), data...), `","recipients":["a@example.com"]}`...))
	})
}

// The message decoded for a repeated "message" key replaces the earlier one, whose
// charge is freed; a refused charge refuses the request.
func TestJSONMessageBudget(t *testing.T) {
	budget := server.NewSessionMemoryTracker(0)
	d := &deliverMailReader{budget: budget}
	_, message, err := d.json(strings.NewReader(`{"message":"` + strings.Repeat("a", 1000) + `","message":"` + strings.Repeat("b", 10) + `"}`))
	if err != nil || string(message) != strings.Repeat("b", 10) {
		t.Fatalf("message %q, err %v", message, err)
	}
	if d.held != 10 || budget.Current() != 10 {
		t.Fatalf("%d bytes held (budget %d) after the last of two messages, want its 10", d.held, budget.Current())
	}

	// The body fits (a 32 KiB buffer); the decoded 20000-byte message beside it does not.
	budget = server.NewSessionMemoryTracker(40 << 10)
	d = &deliverMailReader{budget: budget}
	_, message, err = d.json(strings.NewReader(`{"message":"` + strings.Repeat("a", 20000) + `"}`))
	if !errors.Is(err, server.ErrMemoryBudgetExhausted) || message != nil {
		t.Fatalf("err = %v, message of %d bytes; want the budget refusal", err, len(message))
	}
	d.release()
	if budget.Current() != 0 {
		t.Fatalf("%d bytes charged after release", budget.Current())
	}

	// Invalid UTF-8 grows when decoded (each byte becomes U+FFFD): the charge is the
	// decoded size, not the encoded one.
	budget = server.NewSessionMemoryTracker(0)
	d = &deliverMailReader{budget: budget}
	_, message, err = d.json(strings.NewReader("{\"message\":\"" + strings.Repeat("\xff", 100) + "\"}"))
	if err != nil || len(message) != 300 || d.held != 300 {
		t.Fatalf("message of %d bytes, %d held, err %v; want 300 and 300", len(message), d.held, err)
	}
}

// The handler's answers for requests it cannot read: 400 for the request's own
// faults, as before, and 503 with Retry-After when the budget cannot hold it.
func TestDeliverMailRequestRefusals(t *testing.T) {
	message := "From: a@example.com\r\n\r\n" + strings.Repeat("0123456789abcdef", 8<<10) // 128 KiB
	formType, form := buildForm(t, formPart{name: "recipients", value: "one@example.com"}, formPart{name: "message", value: message})
	fileType, fileForm := buildForm(t, formPart{name: "recipients", value: "one@example.com"}, formPart{name: "message", filename: "m.eml", value: message})
	jsonBody, err := json.Marshal(DeliverMailRequest{Message: message, Recipients: []string{"one@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	forms := []struct {
		name, contentType string
		body              []byte
	}{
		{"raw", "message/rfc822", []byte(message)},
		{"json", "application/json", jsonBody},
		{"multipart form value", formType, form},
		{"multipart file", fileType, fileForm},
	}
	deliver := func(s *Server, contentType string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/admin/mail/deliver?recipients=one@example.com", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		s.handleDeliverMail(rec, req)
		return rec
	}

	for _, f := range forms {
		t.Run(f.name+": read in full on a node that can take it", func(t *testing.T) {
			rec := deliver(&Server{deliveryMemory: server.NewSessionMemoryTracker(0)}, f.contentType, f.body)
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "no upload worker") {
				t.Fatalf("status %d %s; want the request read, then the 503 of a node without an upload worker", rec.Code, rec.Body.String())
			}
		})
		t.Run(f.name+": over the delivery memory budget", func(t *testing.T) {
			budget := server.NewSessionMemoryTracker(100 << 10)
			rec := deliver(&Server{deliveryMemory: budget}, f.contentType, f.body)
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "Delivery memory limit reached") {
				t.Fatalf("status %d, Retry-After %q, %s; want 503 Delivery memory limit reached", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
			}
			if budget.Current() != 0 {
				t.Fatalf("the refused request left %d bytes charged", budget.Current())
			}
		})
		t.Run(f.name+": over max_message_size", func(t *testing.T) {
			rec := deliver(&Server{maxMessageSize: 64 << 10}, f.contentType, f.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d %s; want 400", rec.Code, rec.Body.String())
			}
		})
		t.Run(f.name+": cut short", func(t *testing.T) {
			if f.name == "raw" {
				t.Skip("a raw body has no end to miss")
			}
			rec := deliver(&Server{}, f.contentType, f.body[:len(f.body)-20])
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d %s; want 400", rec.Code, rec.Body.String())
			}
		})
	}

	for name, tc := range map[string]struct{ contentType, body, want string }{
		"invalid json":          {"application/json", `{"message":`, "Invalid JSON"},
		"json message number":   {"application/json", `{"message":5}`, "Invalid JSON"},
		"json without message":  {"application/json", `{"recipients":["one@example.com"]}`, "Message body is required"},
		"json null":             {"application/json", `null`, "Message body is required"},
		"form without message":  {formType, string(form[:bytes.Index(form, []byte("\r\n--"+strings.TrimPrefix(formType, "multipart/form-data; boundary=")+"\r\nContent-Disposition: form-data; name=\"message\""))]) + "\r\n--" + strings.TrimPrefix(formType, "multipart/form-data; boundary=") + "--\r\n", "Message body is required"},
		"form without boundary": {"multipart/form-data", string(form), "Failed to parse multipart form"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := deliver(&Server{}, tc.contentType, []byte(tc.body))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("status %d %s; want 400 %s", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
}

// FuzzDeliverMailMultipart holds the streaming multipart reader to what
// ParseMultipartForm gave the handler, for any body under the boundary "b": both
// refuse it, or both give the same message, recipients and sender. The one
// intended difference is a recipients or from value over maxDeliverFormField,
// which only the streaming reader refuses.
func FuzzDeliverMailMultipart(f *testing.F) {
	const contentType = "multipart/form-data; boundary=b"
	part := func(disposition, extra, value string) string {
		return "--b\r\nContent-Disposition: " + disposition + "\r\n" + extra + "\r\n" + value + "\r\n"
	}
	message := part(`form-data; name="message"`, "", "From: a@example.com\r\n\r\nbody")
	file := part(`form-data; name="message"; filename="m.eml"`, "Content-Type: message/rfc822\r\n", "From: a@example.com\r\n\r\nfile")
	recipients := part(`form-data; name="recipients"`, "", "one@example.com")
	from := part(`form-data; name="from"`, "", "s@example.com")
	for _, seed := range []string{
		recipients + from + message + "--b--\r\n",
		file + recipients + message + from + file + "--b--\r\n",
		"preamble\r\n" + message + recipients + recipients + "--b--\r\nepilogue",
		part(`form-data; name="message"`, "Content-Transfer-Encoding: quoted-printable\r\n", "a=\r\nb=41") + "--b--\r\n",
		part(`form-data; name="message"; filename=""`, "", "value") + part(`attachment; name="x"`, "", "y") + "--b--\r\n",
		part(`form-data; name="recipients"`, "", strings.Repeat("r", maxDeliverFormField+1)) + message + "--b--\r\n",
		message + "--b\r\n",
		message,
		"--b--\r\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		wantReq, wantMessage, ok := parseFormAsBefore(t, contentType, body)
		d := &deliverMailReader{budget: server.NewSessionMemoryTracker(0)}
		req, message, err := d.multipart(formRequest(contentType, body))
		if ok {
			for _, v := range append(append([]string{}, wantReq.Recipients...), wantReq.From) {
				if len(v) > maxDeliverFormField {
					var bad deliverRequestError
					if !errors.As(err, &bad) {
						t.Fatalf("a form field of %d bytes was not refused: %v", len(v), err)
					}
					return
				}
			}
		}
		if (err == nil) != ok {
			t.Fatalf("err = %v, ParseMultipartForm accepted: %v", err, ok)
		}
		if err != nil {
			return
		}
		if string(message) != string(wantMessage) || !reflect.DeepEqual(req, wantReq) {
			t.Fatalf("message %q, request %+v; ParseMultipartForm gave %q, %+v", message, req, wantMessage, wantReq)
		}
	})
}
