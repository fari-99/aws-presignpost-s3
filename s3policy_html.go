package s3Presign

import (
	"bytes"
	"html/template"
)

var htmlDocuments = `
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
</head>
<body>
  <h1>AWS S3 File Uploader</h1>
  <form action="{{.Url}}" method="post" enctype="multipart/form-data">
	{{ range $val := .FormData }}
		<input type="hidden" name="{{ $val.FormName }}" value="{{ .FormValue }}" />
    {{ end }}

	<h3>File</h3>
    <input type="file"   name="file" /> <br/>
    <!-- The elements after this will be ignored -->
    <input type="submit" name="submit" value="Upload to Amazon S3" />
  </form>
</body>
</html>
`

type Forms struct {
	Url      string
	FormData []FormData
}

type FormData struct {
	FormName  string
	FormValue string
}

func GenerateFormHtml(formData Forms) (string, error) {
	htmlTemplate, err := template.New("presign").Parse(htmlDocuments)
	if err != nil {
		return "", err
	}

	bodyBuffer := bytes.NewBufferString("")
	err = htmlTemplate.Execute(bodyBuffer, formData)
	if err != nil {
		return "", err
	}

	return bodyBuffer.String(), nil
}
