const openButton=document.getElementById("detailButton");
const closeButton=document.getElementById("closeDetail");
const panel=document.getElementById("detailPanel");
function openPanel(){panel.hidden=false;openButton.setAttribute("aria-expanded","true");closeButton.focus()}
function closePanel(){panel.hidden=true;openButton.setAttribute("aria-expanded","false");openButton.focus()}
openButton.addEventListener("click",openPanel);
closeButton.addEventListener("click",closePanel);
panel.addEventListener("click",e=>{if(e.target===panel)closePanel()});
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&!panel.hidden)closePanel()});

