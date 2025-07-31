require ["fileinto"];

if exists "X-Spam" {
    fileinto "Junk";
} else {
    keep;
}
