function goDashboard(){
  event.preventDefault();
  window.location.href="dashboard.html";
}

function searchTable(input){
  let filter = input.value.toLowerCase();
  let rows = document.querySelectorAll("#elecTable tr");

  rows.forEach((row, index) => {
    if(index === 0) return;
    let text = row.innerText.toLowerCase();
    row.style.display = text.includes(filter) ? "" : "none";
  });
}