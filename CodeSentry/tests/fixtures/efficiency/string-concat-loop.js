function buildReport(items) {
  let report = '';
  // Inefficient string concatenation in loop
  for (let i = 0; i < items.length; i++) {
    report += items[i].name + ': ' + items[i].value + '\n';
  }
  return report;
}

function generateHTML(rows) {
  let html = '<table>';
  // String concatenation in loop
  for (const row of rows) {
    html += '<tr>';
    html += '<td>' + row.name + '</td>';
    html += '<td>' + row.value + '</td>';
    html += '</tr>';
  }
  html += '</table>';
  return html;
}

module.exports = { buildReport, generateHTML };
