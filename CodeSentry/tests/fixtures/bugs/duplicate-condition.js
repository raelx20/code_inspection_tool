function getDiscount(user) {
  if (user.isPremium) {
    return 0.2;
  } else if (user.isPremium) {
    // Duplicate condition - dead code
    return 0.1;
  } else {
    return 0;
  }
}

function processOrder(order) {
  if (order.total > 100) {
    return 'free-shipping';
  } else if (order.total > 100) {
    // Duplicate - never reached
    return 'discount-shipping';
  } else {
    return 'standard-shipping';
  }
}

module.exports = { getDiscount, processOrder };
