pub fn get_app_html() -> String {
    let index = include_str!("index.html");
    let css = include_str!("style.css");
    let js = include_str!("app.js");
    let logo_base64 = include_str!("../../assets/logo_base64.txt");

    let logo_data_uri = format!("data:image/png;base64,{}", logo_base64.trim());

    index
        .replace(
            "<link rel=\"stylesheet\" href=\"style.css\">",
            &format!("<style>{}</style>", css),
        )
        .replace(
            "<script src=\"app.js\"></script>",
            &format!("<script>{}</script>", js),
        )
        .replace("src=\"logo.png\"", &format!("src=\"{}\"", logo_data_uri))
}
