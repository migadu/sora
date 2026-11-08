package helpers

import "testing"

func TestAttachmentKeyword_FilenameParameters(t *testing.T) {
	for _, tc := range []struct {
		name, disposition string
		want              attachmentResult
	}{
		{"plain", `inline; filename="report.pdf"`, attachmentFound},
		{"quoted semicolon", `inline; filename="report; final.pdf"`, attachmentFound},
		{"quoted escape", `inline; filename="report\"; final.pdf"`, attachmentFound},
		{"parameter text inside another value", `inline; description="notes; filename*=iso-8859-1''%E4.pdf"`, attachmentNone},
		{"invalid quoted disposition", `"inline; filename=report.pdf`, attachmentUnknown},
		{"invalid disposition token sequence", `x-custom garbage`, attachmentUnknown},
		{"malformed legacy with valid extended", `inline; filename=quarterly report.pdf; filename*=UTF-8''quarterly%20report.pdf`, attachmentFound},
		{"valid legacy with malformed extended", `inline; filename="quarterly report.pdf"; filename*=UTF-8''quarterly report.pdf`, attachmentFound},
		{"invalid extended before valid legacy", `inline; filename*=UTF-8''bad%ZZ; filename="report.pdf"`, attachmentFound},
		{"invalid extended after valid continuation", `inline; filename*0="report"; filename*1=".pdf"; filename*=UTF-8''bad%ZZ`, attachmentFound},
		{"latin1", `inline; filename*=iso-8859-1''%E4.pdf`, attachmentFound},
		{"windows", `inline; filename*=windows-1252''%80.pdf`, attachmentFound},
		{"japanese", `inline; filename*=iso-2022-jp'ja'%1B%24Breport.pdf`, attachmentFound},
		{"unspecified charset", `inline; filename*=''report.pdf`, attachmentFound},
		{"encoded empty", `inline; filename*=iso-8859-1''`, attachmentNone},
		{"plain empty", `inline; filename=""`, attachmentNone},
		{"encoded continuation", `inline; filename*1*=.pdf; filename*0*=iso-8859-1''%E4`, attachmentFound},
		{"mixed continuation", `inline; filename*0*=''report; filename*1=" final.pdf"`, attachmentFound},
		{"plain continuation", `inline; filename*0="report"; filename*1=".pdf"`, attachmentFound},
		{"empty continuation", `inline; filename*0*=''; filename*1=""`, attachmentNone},
		{"invalid percent escape", `inline; filename*=iso-8859-1''%ZZ.pdf`, attachmentUnknown},
		{"missing first segment", `inline; filename*1*=report.pdf`, attachmentUnknown},
		{"gap in continuation", `inline; filename*0*=''report; filename*2*=.pdf`, attachmentUnknown},
		{"oversized index", `inline; filename*999999999999999999999=report.pdf`, attachmentUnknown},
		{"conflicting continuation", `inline; filename*0="a"; filename*0*=''b`, attachmentUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("Content-Type: application/pdf\r\nContent-Disposition: " + tc.disposition + "\r\n\r\nPDF")
			keyword, known := AttachmentKeyword(data)
			switch tc.want {
			case attachmentFound:
				if !known || keyword != KeywordHasAttachment {
					t.Fatalf("got %q, %v; want attachment", keyword, known)
				}
			case attachmentNone:
				if !known || keyword != KeywordHasNoAttachment {
					t.Fatalf("got %q, %v; want no attachment", keyword, known)
				}
			default:
				if known {
					t.Fatalf("got %q; want unknown", keyword)
				}
			}
		})
	}
}
