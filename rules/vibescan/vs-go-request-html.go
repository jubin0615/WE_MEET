package example
import ("net/http"; "html/template")
func render(r *http.Request) {
    // ruleid: vs-go-request-html
    _ = template.HTML(r.FormValue("text"))
    // ok: vs-go-request-html
    _ = r.FormValue("text")
}
