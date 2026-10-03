function setupHandlers(element) {
  // Event listeners added without cleanup
  element.addEventListener('click', handleClick);
  element.addEventListener('mouseover', handleHover);
  element.addEventListener('keydown', handleKeydown);
  // No removeEventListener calls anywhere
}

function handleClick(e) { console.log('click'); }
function handleHover(e) { console.log('hover'); }
function handleKeydown(e) { console.log('key'); }

module.exports = { setupHandlers };
