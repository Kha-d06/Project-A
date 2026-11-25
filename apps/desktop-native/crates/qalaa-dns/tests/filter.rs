use qalaa_dns::{clean_name, normalise_line, DnsFilter};

const LIST: &str = "\
! Title: test list
||ads.example^
||tracker.example^$third-party
||example.org/banner/
@@||good.ads.example^
||cdn.example^
||cdn.example^$badfilter
||important.example^$important
@@||important.example^
0.0.0.0 malware.test
127.0.0.1 localhost
example.com##.ad-banner
/^ad[0-9]+\\.example$/
";

fn filter() -> DnsFilter {
    DnsFilter::from_lists([LIST])
}

#[test]
fn whole_host_rules_block_the_name_and_its_subdomains() {
    let f = filter();
    assert!(f.check("ads.example").blocked);
    assert!(f.check("x.ads.example.").blocked, "subdomains and a trailing dot");
    assert!(f.check("malware.test").blocked, "hosts-file lines");
    assert!(!f.check("example.net").blocked);
}

#[test]
fn rules_that_need_more_than_a_name_dont_block_at_dns() {
    let f = filter();
    assert!(!f.check("tracker.example").blocked, "$third-party needs the page");
    assert!(!f.check("example.org").blocked, "a path rule needs the URL");
    assert!(!f.check("example.com").blocked, "cosmetic rules are for the page");
}

#[test]
fn exceptions_important_and_badfilter_behave_as_in_the_browser() {
    let f = filter();
    let good = f.check("good.ads.example");
    assert!(!good.blocked && good.excepted);
    assert!(!f.check("cdn.example").blocked, "$badfilter cancels the rule");
    assert!(f.check("important.example").blocked, "$important beats the exception");
}

#[test]
fn odd_input_is_never_blocked_or_crashed_on() {
    let f = filter();
    for bad in ["", "..", "a b", "x".repeat(300).as_str(), "ads.example/path", "😀.example"] {
        assert!(!f.check(bad).blocked, "{bad:?}");
    }
    assert_eq!(clean_name("Ads.Example."), Some("ads.example".into()));
    assert_eq!(normalise_line("0.0.0.0 Tracker.Example"), Some("||tracker.example^".into()));
    assert_eq!(normalise_line("127.0.0.1 localhost"), None);
    assert_eq!(normalise_line("! comment"), None);
}

#[test]
fn several_lists_combine() {
    let f = DnsFilter::from_lists(["||a.example^", "||b.example^\n@@||ok.a.example^"]);
    assert!(f.check("a.example").blocked && f.check("b.example").blocked);
    assert!(!f.check("ok.a.example").blocked);
    assert_eq!(f.rules, 3);
}
