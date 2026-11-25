(function () {
  "use strict";
  var buttons = document.querySelectorAll(".filter-btn");
  var items = document.querySelectorAll(".post-item");

  buttons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      buttons.forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");

      var category = btn.getAttribute("data-category");
      items.forEach(function (item) {
        var show = category === "all" || item.getAttribute("data-category") === category;
        item.style.display = show ? "" : "none";
      });
    });
  });
})();
