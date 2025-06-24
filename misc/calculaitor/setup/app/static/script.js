
var loading = false;
var display = document.getElementById("display");

function append(value) {
  if (loading) return;
  display.value += value;
}

function wrapFunc(funcName) {
  if (loading) return;
  display.value = `${funcName}(${display.value})`;
}

function clearDisplay() {
  if (loading) return;
  display.value = '';
}

function calculate() {
  if (loading) return;
  const equation = display.value;
  if (equation.length <= 0) return;
  loading = true;

  fetch('/calculate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ equation })
  })
  .then(res => res.json())
  .then(data => {
    loading = false;
    display.value = data.result;
  })
  .catch(err => {
    loading = false;
    console.error(err);
    display.value = 'ERROR';
  });
}
