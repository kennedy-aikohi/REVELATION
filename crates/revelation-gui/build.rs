fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("../../assets/revelation.ico");
    res.compile().unwrap();
}
