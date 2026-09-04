package billing

import (
	"context"
	"fmt"
	"os"

	"github.com/stripe/stripe-go/v82"
	portalsession "github.com/stripe/stripe-go/v82/billingportal/session"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
	"github.com/stripe/stripe-go/v82/webhook"
	"github.com/Ayoshiss/sentinel-subnet/gateway/db"
)

// CreatePortalSession returns a Stripe-hosted Customer Portal URL where the
// customer can manage payment methods, view invoices, and download receipts.
func CreatePortalSession(ctx context.Context, customerID, email, returnURL string) (string, error) {
	stripeCustomerID, err := ensureStripeCustomer(ctx, customerID, email)
	if err != nil {
		return "", fmt.Errorf("stripe customer: %w", err)
	}
	s, err := portalsession.New(&stripe.BillingPortalSessionParams{
		Customer:  stripe.String(stripeCustomerID),
		ReturnURL: stripe.String(returnURL),
	})
	if err != nil {
		return "", fmt.Errorf("portal session: %w", err)
	}
	return s.URL, nil
}

func init() {
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
}

// CreditPack defines a purchasable credit bundle.
type CreditPack struct {
	Name      string
	AmountUSD int64 // in cents
	Credits   float64 // USD credited to balance
	PriceID   string  // Stripe Price ID (set after creating prices)
}

var CreditPacks = []CreditPack{
	{Name: "Starter", AmountUSD: 1000,  Credits: 10.00},  // $10
	{Name: "Builder", AmountUSD: 5000,  Credits: 50.00},  // $50
	{Name: "Scale",   AmountUSD: 10000, Credits: 100.00}, // $100
}

// CreateCheckoutSession creates a Stripe Checkout session for a credit pack.
func CreateCheckoutSession(ctx context.Context, customerID, email, packName, appURL string) (string, error) {
	// Find the pack
	var pack *CreditPack
	for i := range CreditPacks {
		if CreditPacks[i].Name == packName {
			pack = &CreditPacks[i]
			break
		}
	}
	if pack == nil {
		return "", fmt.Errorf("unknown pack: %s", packName)
	}

	// Get or create Stripe customer
	stripeCustomerID, err := ensureStripeCustomer(ctx, customerID, email)
	if err != nil {
		return "", fmt.Errorf("stripe customer: %w", err)
	}

	params := &stripe.CheckoutSessionParams{
		Customer: stripe.String(stripeCustomerID),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency: stripe.String("usd"),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name:        stripe.String(fmt.Sprintf("TAO Gateway, %s credits ($%.0f)", pack.Name, pack.Credits)),
						Description: stripe.String(fmt.Sprintf("$%.2f in API credits for TAO Gateway inference", pack.Credits)),
					},
					UnitAmount: stripe.Int64(pack.AmountUSD),
				},
				Quantity: stripe.Int64(1),
			},
		},
		Mode:       stripe.String(string(stripe.CheckoutSessionModePayment)),
		SuccessURL: stripe.String(appURL + "/dashboard?payment=success"),
		CancelURL:  stripe.String(appURL + "/dashboard?payment=cancelled"),
		Metadata: map[string]string{
			"customer_id": customerID,
			"pack":        packName,
			"credits_usd": fmt.Sprintf("%.2f", pack.Credits),
		},
	}

	sess, err := session.New(params)
	if err != nil {
		return "", fmt.Errorf("stripe session: %w", err)
	}

	// Record pending purchase
	_, err = db.Pool.Exec(ctx, `
		INSERT INTO credit_purchases (customer_id, stripe_session_id, amount_usd, credits_usd, status)
		VALUES ($1, $2, $3, $4, 'pending')
	`, customerID, sess.ID, float64(pack.AmountUSD)/100, pack.Credits)
	if err != nil {
		return "", fmt.Errorf("record purchase: %w", err)
	}

	return sess.URL, nil
}

// HandleWebhook processes Stripe webhook events.
func HandleWebhook(payload []byte, signature string) error {
	webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	event, err := webhook.ConstructEventWithOptions(payload, signature, webhookSecret,
		webhook.ConstructEventOptions{IgnoreAPIVersionMismatch: true})
	if err != nil {
		return fmt.Errorf("webhook verify: %w", err)
	}

	if event.Type == "checkout.session.completed" {
		sess, ok := event.Data.Object["id"].(string)
		if !ok {
			return fmt.Errorf("missing session id")
		}
		// Re-fetch the full session to get metadata
		fullSess, err := session.Get(sess, nil)
		if err != nil {
			return fmt.Errorf("fetch session: %w", err)
		}
		return fulfillPurchase(context.Background(), fullSess)
	}

	return nil
}

// fulfillPurchase credits the customer's balance after successful payment.
func fulfillPurchase(ctx context.Context, sess *stripe.CheckoutSession) error {
	customerID := sess.Metadata["customer_id"]

	// Update purchase + add credits atomically
	_, err := db.Pool.Exec(ctx, `
		WITH updated AS (
			UPDATE credit_purchases
			SET status = 'paid', paid_at = NOW(), stripe_payment_intent = $2
			WHERE stripe_session_id = $1 AND status = 'pending'
			RETURNING credits_usd
		)
		UPDATE customers
		SET balance_usd = balance_usd + (SELECT credits_usd FROM updated)
		WHERE id = $3
	`, sess.ID, sess.PaymentIntent.ID, customerID)
	return err
}

// GetBalance returns a customer's current credit balance.
func GetBalance(ctx context.Context, customerID string) (float64, error) {
	var balance float64
	err := db.Pool.QueryRow(ctx,
		`SELECT balance_usd FROM customers WHERE id = $1`, customerID,
	).Scan(&balance)
	return balance, err
}

// DeductBalance deducts usage cost from the customer balance.
// Returns error if balance is insufficient.
func DeductBalance(ctx context.Context, customerID string, costUSD float64) error {
	result, err := db.Pool.Exec(ctx, `
		UPDATE customers
		SET balance_usd = balance_usd - $2
		WHERE id = $1 AND balance_usd >= $2
	`, customerID, costUSD)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("insufficient balance")
	}
	return nil
}

func ensureStripeCustomer(ctx context.Context, customerID, email string) (string, error) {
	// Check if already has a stripe customer
	var stripeID *string
	db.Pool.QueryRow(ctx, `SELECT stripe_customer_id FROM customers WHERE id = $1`, customerID).Scan(&stripeID)
	if stripeID != nil && *stripeID != "" {
		return *stripeID, nil
	}

	// Create new Stripe customer
	params := &stripe.CustomerParams{
		Email: stripe.String(email),
		Metadata: map[string]string{"tao_customer_id": customerID},
	}
	c, err := customer.New(params)
	if err != nil {
		return "", err
	}

	// Save stripe customer ID
	db.Pool.Exec(ctx, `UPDATE customers SET stripe_customer_id = $1 WHERE id = $2`, c.ID, customerID)
	return c.ID, nil
}
