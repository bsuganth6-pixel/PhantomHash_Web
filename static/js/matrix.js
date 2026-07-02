// PhantomHash — Matrix rain background
(function () {
  const canvas = document.getElementById("matrix-bg");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  function resize() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
  resize(); window.addEventListener("resize", resize);
  const chars = "01ハッシュPHANTOMHASH256512"; const fs = 14; let cols, drops;
  function setup() { cols = Math.floor(canvas.width / fs); drops = Array.from({length:cols}, () => Math.random() * -50); }
  setup(); window.addEventListener("resize", setup);
  const colors = ["#00F5FF","#9B5DE5","#00FF88"];
  function draw() {
    ctx.fillStyle="rgba(6,6,8,0.06)"; ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.font=`${fs}px JetBrains Mono,monospace`;
    for(let i=0;i<cols;i++){
      ctx.fillStyle=colors[Math.floor(Math.random()*colors.length)];
      ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*fs,drops[i]*fs);
      if(drops[i]*fs>canvas.height&&Math.random()>0.975) drops[i]=0;
      drops[i]++;
    }
  }
  setInterval(draw,45);
})();
