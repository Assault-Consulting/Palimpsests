### Fixed

- **The HTML report does not call an empty container "sound as far as
  checked".** For an empty file read without an anchor the report's verdict
  is `partial` (format `/1` has no other word for it), and the page printed
  the general gloss for `partial` beside it. With the `empty_container`
  diagnosis the page now says the container holds no records — nothing was
  checked, and nothing was found intact. The verdict and the report's JSON
  are unchanged; `/2` gives this case its own verdict. Raised by Auditor.
