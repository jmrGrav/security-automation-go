package baseline

import "testing"

func TestNewArleoEUBaselineMatch(t *testing.T) {
	m := NewArleoEUBaseline()
	if _, ok := m.Match("/favicon.ico"); !ok {
		t.Fatal("expected favicon to match baseline")
	}
	if _, ok := m.Match("/assets/app.css"); !ok {
		t.Fatal("expected asset prefix to match baseline")
	}
	if _, ok := m.Match("/wp-login.php"); ok {
		t.Fatal("did not expect wordpress probe to match baseline")
	}
}
