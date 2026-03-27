#![allow(dead_code, unused_imports)]

use std::fmt::Display;

use thiserror::Error;
use winnow::ModalResult;
use winnow::combinator::{alt, cut_err, dispatch, empty, fail, preceded};
use winnow::error::{ContextError, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::token::{rest, take, take_until, take_while};

macro_rules! list {
    ($a:literal) => {
        quote!()
    };
    ($a:literal, $b:literal) => {
        concat!('`', $a, "` or `", $b, '`')
    };
    ($head:literal,  $($tail:literal),+) => {
        concat!(concat!('`', $head, '`'), ", ", list!($($tail),*))
    };
}

macro_rules! choice {
    ($name:ident; $description:literal; $($opt:literal),+ ) => {
        fn $name<'s>(input: &mut &'s str) -> ModalResult<&'s str> {
            alt(($($opt),+,fail)).context(StrContext::Label($description)).context(StrContext::Expected(StrContextValue::StringLiteral(concat!( "one of: ", list!($($opt),+))))).parse_next(input)
        }
    };
}

choice!(std_role; "Std role"; "term", "label");
choice!(py_role; "Python role"; "class", "method", "function");

#[derive(PartialEq, Debug)]
pub enum StdRole {
    Label,
    Term,
}

fn sphinx_type<'s>(input: &mut &'s str) -> Result<&'s str, anyhow::Error> {
    dispatch! { take_until(0..,':');
    "std" => cut_err(preceded(":", std_role).context(StrContext::Label("foo"))),
    "py" => cut_err(preceded(":", py_role)),
        _ => fail,}
    .context(StrContext::Label("type"))
    .parse(input)
    .map_err(|e| anyhow::format_err!("{e}"))
}

#[cfg(test)]
mod test {

    use winnow::error::{ContextError, StrContextValue};

    use super::*;

    #[test]
    fn winnow_std_domain_asdf() {
        let mut haystack = "std::";
        let result = sphinx_type(&mut haystack);

        assert_eq!(haystack, "std::");
        dbg!(result);
        panic!();
        // assert_eq!(result, Ok(":"));
    }
    #[test]
    fn winnow_py_domain() {
        let mut haystack = "py:method";
        let result = sphinx_type(&mut haystack);

        dbg!(result);
        assert_eq!(haystack, "");
        // assert_eq!(result, Ok("method"));
    }

    #[test]
    fn winnow_std_role_invalid() {
        let mut haystack = "std:asdf";
        let result = sphinx_type(&mut haystack);

        assert_eq!(haystack, "std:asdf");
        println!("{}", result.unwrap_err().to_string());
        // assert_eq!(
        //     result.unwrap_err().to_string(),
        //     "std:asdf\n    ^\ninvalid Std role\nexpected `one of: `term` or `label``".to_string()
        // );
        panic!();
    }
    #[test]
    fn winnow_std_role() {
        let mut haystack = "term";
        let result = std_role(&mut haystack);

        assert_eq!(haystack, "");
        dbg!(result);
        // assert_eq!(result, Ok(StdRole::Term));
    }
    #[test]
    fn winnow_std_domain() {
        let mut haystack = "std:label";
        let result = sphinx_type(&mut haystack);

        dbg!(result);
        assert_eq!(haystack, "");
        // assert_eq!(result, Ok("label"));
    }
}
