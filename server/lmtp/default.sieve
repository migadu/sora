require "fileinto";
require "envelope";
require "mailbox";
require "subaddress";
require "variables";

if anyof(
  header :contains "X-Spam" "Yes"
) {
  fileinto "Junk";
  stop;
}

if envelope :matches :detail "To" "*" {
  set :lower "detail" "${1}";
  fileinto :create "${detail}";
}
