//RFC 3986 impl
use nom::{
    IResult,
    character::complete::{char, one_of, satisfy, digit0},
    bytes::complete::{tag},
    combinator::{opt, recognize, map, all_consuming},
    sequence::{pair, tuple},
    multi::{many0, many1, many_m_n},
    branch::{alt},
};

use std::net::{Ipv4Addr, Ipv6Addr};

//uri type
#[derive(Debug)]
pub struct Uri<'a> {
    scheme: &'a str,
    hier_part: HierPart<'a>,
    query: Option<&'a str>,
    fragment: Option<&'a str>
}

impl<'a> Uri<'a> {
    pub fn scheme(&self) -> &'a str { self.scheme }
    pub fn user_info(&self) -> Option<&'a str> { self.hier_part.authority.user_info }
    pub fn query(&self) -> Option<&'a str> { self.query }
    pub fn fragment(&self) -> Option<&'a str> { self.fragment }
    pub fn host(&self) -> &Host<'a> { &self.hier_part.authority.host }
    pub fn port(&self) -> Option<u16> { self.hier_part.authority.port }
    pub fn domain(&self) -> Option<&'a str> { match self.hier_part.authority.host {
        Host::RegName(domain) => Some(domain),
        _ => None
    }}
}

#[derive(Debug)]
struct HierPart<'a> {
    authority: Authority<'a>,
    hier_path: &'a str
}

#[derive(Debug)]
struct Authority<'a> {
    user_info: Option<&'a str>,
    host: Host<'a>,
    port: Option<u16>
}

#[derive(Debug)]
pub enum Host<'a> { IpLiteral(IpLiteral<'a>), Ipv4Addr(Ipv4Addr), RegName(&'a str)}

#[derive(Debug)]
pub enum IpLiteral<'a> { Ipv6Addr(Ipv6Addr), IpFuture(&'a str) }

//TODO: Convert nom error to uri error
pub fn parse(input: & str) -> Result<Uri, &str> { uri()(input).map_or( Err("TODO: Error Handling"), |(_, uri)| Ok(uri)) }

//TODO: Uri Builder
pub struct UriBuilder {}

impl<'a> UriBuilder {
    fn new() -> Self { UriBuilder {} }
}

fn uri<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, Uri<'a>> {
    all_consuming(map(
        tuple((
            scheme(), 
            char(':'), 
            hier_part(), 
            opt(recognize(pair(char('?'), fragment_query()))),
            opt(recognize(pair(char('#'), fragment_query())))
        )),
        |(scheme, _, hier_part, query, fragment)| { Uri { 
            scheme, 
            hier_part, 
            query: query.and_then(|c| Some(&c[1..])), 
            fragment: fragment.and_then(|c| Some(&c[1..]))
        }}
    ))
}

//scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
fn scheme<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(pair(alpha(), many0(alt((alpha(), digit(), one_of("+-."))))))
}

//hier-part   = "//" authority path-abempty
//             / path-absolute
//             / path-rootless
//             / path-empty
fn hier_part<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, HierPart<'a>> {
    map(
        tuple((
            tag("//"),
            authority(),
            alt((path_abempty(), path_absolute(), path_rootless(), path_empty()))
        )),
        |(_, authority, hier_path)| { HierPart { authority, hier_path } }
    )
}

//authority   = [ userinfo "@" ] host [ ":" port ]
//userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
//host          = IP-literal / IPv4address / reg-name
//port          = *DIGIT
fn authority<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, Authority<'a>> {
    map(
        tuple((
            opt(recognize(pair(user_info(), char('@')))),
            host(),
            opt(recognize(pair(char(':'), port()))),
        )),

        |(user_info, host, port)| {
            Authority {
                user_info: user_info.and_then(|c| Some(&c[..c.len()-1])), 
                host,
                port: port.and_then(|c| Some((&c[1..]).parse::<u16>().unwrap())), 
            }
        }
    )
}

fn user_info<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(many0(alt((unreserved(), pct_encoded(), sub_delims(), recognize(char(':'))))))
}

fn host<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, Host<'a>> {
    alt((ip_literal(), real_ipv4_address(), reg_name()))
}

fn port<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    digit0
}

/*
IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
IPv6address   =                            6( h16 ":" ) ls32
                 /                       "::" 5( h16 ":" ) ls32
                 / [               h16 ] "::" 4( h16 ":" ) ls32
                 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                 / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                 / [ *4( h16 ":" ) h16 ] "::"              ls32
                 / [ *5( h16 ":" ) h16 ] "::"              h16
                 / [ *6( h16 ":" ) h16 ] "::"

h16           = 1*4HEXDIG
ls32          = ( h16 ":" h16 ) / IPv4address
IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
dec-octet     = DIGIT                 ; 0-9
                 / %x31-39 DIGIT         ; 10-99
                 / "1" 2DIGIT            ; 100-199
                 / "2" %x30-34 DIGIT     ; 200-249
                 / "25" %x30-35          ; 250-255
reg-name      = *( unreserved / pct-encoded / sub-delims )
*/

fn ip_literal<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, Host<'a>> {
    map(
        tuple((
            char('['), 
            alt((real_ipv6_address(), ipv_future())),
            char(']')
        )),
        |(_, ip_literal, _)| Host::IpLiteral(ip_literal)
    )
}

fn ipv_future<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, IpLiteral> {
    map(
        recognize(tuple((
            char('v'),
            many1(hex_dig()),
            char('.'),
            many1(alt((unreserved(), sub_delims(), recognize(char(':')))))
        ))),
        |ip_future| IpLiteral::IpFuture(ip_future)
    )
}

fn ipv6_address<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    alt(( 
        recognize(pair(many_m_n(6, 6, pair(h16(), char(':'))), ls32())),
        recognize(tuple((tag("::"), many_m_n(5, 5, pair(h16(), char(':'))), ls32()))),
        recognize(tuple((opt(h16()), tag("::"), many_m_n(4, 4, pair(h16(), char(':'))), ls32()))),
        recognize(tuple((opt(many_m_n(0, 1, h16_colon())), tag("::"), many_m_n(3, 3, h16_colon()), ls32()))),
        recognize(tuple((opt(many_m_n(0, 2, h16_colon())), tag("::"), many_m_n(2, 3, h16_colon()), ls32()))),
        recognize(tuple((opt(many_m_n(0, 3, h16_colon())), tag("::"), h16_colon(), ls32()))),
        recognize(tuple((opt(many_m_n(0, 4, h16_colon())), tag("::"), ls32()))),
        recognize(tuple((opt(many_m_n(0, 5, h16_colon())), tag("::"), h16()))),
        recognize(tuple((opt(many_m_n(0, 6, h16_colon())), tag("::")))),
    ))
}

fn real_ipv6_address<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, IpLiteral> {
    map(
        ipv6_address(),
        |ipv6_addr| {
            IpLiteral::Ipv6Addr(ipv6_addr.parse::<Ipv6Addr>().unwrap())
        }
    )
}

fn h16_colon<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(pair(h16(), char(':')))
}

fn h16<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(many_m_n(1, 4, hex_dig()))
}

fn ls32<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    alt((
        recognize(tuple((h16(), char(':'), h16()))),
        ipv4_address()
    ))
}

fn ipv4_address<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(tuple((dec_octet(), char('.'), dec_octet(), char('.'), dec_octet(), char('.'), dec_octet())))
}

fn real_ipv4_address<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, Host<'a>> {
    map(
        ipv4_address(),
        |ip_addr| Host::Ipv4Addr(ip_addr.parse::<Ipv4Addr>().unwrap())
    )
}

//TODO: Faster to parse to u8 w/ std then match input str w/ map_consumed?
fn dec_octet<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    alt(( 
        recognize(tuple((tag("25"), one_of("012345"), digit()))),
        recognize(tuple((char('2'), one_of("01234"), digit()))),
        recognize(tuple((char('1'), digit(), digit()))),
        recognize(pair(one_of("123456789"), digit())),
        recognize(digit()),
    ))
}

fn reg_name<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, Host<'a>> {
    map(
        recognize(many0(alt((unreserved(), pct_encoded(), sub_delims())))),
        |a| Host::RegName(a)
    )
}

fn hex_dig<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, char> {
    satisfy(|c| c.is_digit(16))
}

//path-abempty  = *( "/" segment )
//path-absolute = "/" [ segment-nz *( "/" segment ) ]
//path-noscheme = segment-nz-nc *( "/" segment )
//path-rootless = segment-nz *( "/" segment )
//path-empty    = 0<pchar>
fn path_abempty<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(many0(pair(char('/'), segment())))
}

fn path_absolute<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(pair(char('/'), opt(pair(segment_nz(), many0(pair(char('/'), segment()))))))
}

fn path_noscheme<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(pair(segment_nz_nc(), many0(pair(char('/'), segment()))))
}

fn path_rootless<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(pair(segment_nz(), many0(pair(char('/'), segment()))))
}

fn path_empty<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    //TODO: Figure out what this rule means
    recognize(char('\0'))
}

//segment       = *pchar
//segment-nz    = 1*pchar
//segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )

fn segment<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(many0(pchar()))
}

fn segment_nz<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(many1(pchar()))
}

fn segment_nz_nc<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(many1(pchar()))
}

//pchar base
//pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
//unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
//pct-encoded   = "%" HEXDIG HEXDIG
//sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="

fn pchar_base<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    alt((unreserved(), pct_encoded(), sub_delims()))
}
    
fn pchar<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    alt((pchar_base(), recognize(one_of(":@"))))
}

fn unreserved<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(alt((
        alpha(),
        digit(),
        one_of("-._~")
    )))
}

fn pct_encoded<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(tuple((char('%'), hex_dig(), hex_dig())))
}

fn sub_delims<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(one_of("!$&'()*+,;="))
}

//fragment / query = *( pchar / "/" / "?" )
fn fragment_query<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    recognize(many0(alt((pchar(), recognize(one_of("/?"))))))
}

//chars
fn alpha<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, char> {
    satisfy(|c| c.is_alphabetic())
}

fn digit<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, char> {
    satisfy(|c| c.is_digit(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time() {
        let mut parser = uri();
        let now = std::time::Instant::now();
        let result = parser("https://www.youtube.com/watch?v=oZWEV3bACZo");
        let elapsed = now.elapsed();

        println!("{:#?}", result);
        println!("in {:?}", elapsed);        
    }

    #[test]
    fn read_me_test() {
        let uri = parse("https://yesman@www.youtube.com:80/?v=12345678#tag").unwrap();
        
        println!("{:?}", uri.scheme()); // "https"
        println!("{:?}", uri.host()); // RegName("www.youtube.com")
        println!("{:?}", uri.user_info()); // Some("yesman")
        println!("{:?}", uri.domain()); // Some("www.youtube.com")
        println!("{:?}", uri.port()); // Some(80)
        println!("{:?}", uri.query()); // Some("v=12345678")
        println!("{:?}", uri.fragment()); // Some("tag")
    }
}