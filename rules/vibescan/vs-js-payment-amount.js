// ruleid: vs-js-payment-amount
stripe.paymentIntents.create({amount: req.body.amount, currency: "krw"});
// ok: vs-js-payment-amount
stripe.paymentIntents.create({amount: order.total, currency: "krw"});
