package consts

// MaxVacationDays is the longest Sieve vacation :days period Sora honours; a larger
// value is used as this one. RFC 5230 §4.1: "Sites MAY also define a maximum days
// value, which MUST be greater than 7, and SHOULD be greater than 30." The vacation
// history must be kept at least this long, or a reply is repeated within its period.
const MaxVacationDays = 365
