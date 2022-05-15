
function copyToClipboard(element, btn) {
  var $temp = $("<textarea>");
  $("body").append($temp);
  $temp.val($(element).text()).select();
  document.execCommand("copy");
  btn.innerHTML = "copied";
  $temp.remove();
}
