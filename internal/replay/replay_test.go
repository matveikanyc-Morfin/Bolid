package replay

import "testing"

func TestFirstPacketAccepted(t *testing.T) {
	f := New(0)
	if !f.ValidateAndAdd(0) {
		t.Fatal("первый пакет (seq=0) должен приниматься")
	}
}

func TestMonotonicAccepted(t *testing.T) {
	f := New(0)
	for seq := uint64(0); seq < 10000; seq++ {
		if !f.ValidateAndAdd(seq) {
			t.Fatalf("монотонно растущий seq=%d должен приниматься", seq)
		}
	}
}

func TestDuplicateRejected(t *testing.T) {
	f := New(0)
	if !f.ValidateAndAdd(5) {
		t.Fatal("seq=5 должен приняться первым")
	}
	if f.ValidateAndAdd(5) {
		t.Fatal("повтор seq=5 должен отвергаться")
	}
}

func TestReorderWithinWindow(t *testing.T) {
	f := New(0)
	// Принимаем 10, затем «опоздавшие» 7,8,9 в перемешку — все свежие.
	if !f.ValidateAndAdd(10) {
		t.Fatal("seq=10")
	}
	for _, s := range []uint64{7, 9, 8, 3, 1} {
		if !f.ValidateAndAdd(s) {
			t.Fatalf("опоздавший свежий seq=%d должен приниматься", s)
		}
	}
	// И их повторы — отвергаются.
	for _, s := range []uint64{10, 7, 9, 8, 3, 1} {
		if f.ValidateAndAdd(s) {
			t.Fatalf("повтор seq=%d должен отвергаться", s)
		}
	}
}

func TestOldBelowWindowRejected(t *testing.T) {
	win := uint64(128)
	f := New(win)
	// Продвигаем окно далеко вперёд.
	if !f.ValidateAndAdd(10000) {
		t.Fatal("seq=10000")
	}
	// Пакет намного ниже окна — устаревший.
	if f.ValidateAndAdd(10000 - f.WindowBits()) {
		t.Fatal("пакет на границе/ниже окна должен отвергаться")
	}
	if f.ValidateAndAdd(0) {
		t.Fatal("очень старый seq=0 должен отвергаться")
	}
}

func TestLargeJumpResetsWindow(t *testing.T) {
	f := New(0)
	if !f.ValidateAndAdd(1) {
		t.Fatal("seq=1")
	}
	// Скачок намного больше окна.
	big := uint64(1_000_000)
	if !f.ValidateAndAdd(big) {
		t.Fatal("большой скачок вперёд должен приниматься")
	}
	// Старые значения после сброса окна — отвергаются.
	if f.ValidateAndAdd(1) {
		t.Fatal("seq=1 после большого скачка — вне окна, отвергнуть")
	}
	// Новое свежее у нового максимума — принимается.
	if !f.ValidateAndAdd(big - 1) {
		t.Fatal("seq чуть ниже нового максимума, но в окне — принять")
	}
}

func TestEdgeOfWindow(t *testing.T) {
	f := New(64) // окно ровно 64 бита
	if !f.ValidateAndAdd(100) {
		t.Fatal("seq=100")
	}
	// seq=100-63=37 ещё в окне (highest-seq=63 < 64).
	if !f.ValidateAndAdd(37) {
		t.Fatal("seq=37 (на дальнем краю окна) должен приниматься")
	}
	// seq=100-64=36 уже вне окна.
	if f.ValidateAndAdd(36) {
		t.Fatal("seq=36 (ровно вне окна) должен отвергаться")
	}
}

func TestWindowRoundsUp(t *testing.T) {
	f := New(100) // округлится вверх до 128
	if f.WindowBits() != 128 {
		t.Fatalf("ожидали окно 128, получили %d", f.WindowBits())
	}
}
