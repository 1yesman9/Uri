### WIP Uri parser & builder

```rs
let uri = lib::parse("https://yesman@www.youtube.com:80/?v=12345678#tag").unwrap();

println!("{:?}", uri.scheme()); // "https"
println!("{:?}", uri.host()); // RegName("www.youtube.com")
println!("{:?}", uri.user_info()); // Some("yesman")
println!("{:?}", uri.domain()); // Some("www.youtube.com")
println!("{:?}", uri.port()); // Some(80)
println!("{:?}", uri.query()); // Some("v=12345678")
println!("{:?}", uri.fragment()); // Some("tag")
```