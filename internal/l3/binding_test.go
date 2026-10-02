package l3

import "testing"

func TestOldUnregisterCannotClearReplacement(t *testing.T) {
	ep := New()
	oldUp := ep.SetUplink(func([]byte) error { t.Fatal("旧上行被调用"); return nil })
	oldDown := ep.SetDownlink(func([]byte) { t.Fatal("旧下行被调用") })
	up, down := 0, 0
	newUp := ep.SetUplink(func([]byte) error { up++; return nil })
	newDown := ep.SetDownlink(func([]byte) { down++ })
	oldUp()
	oldDown()
	oldUp()
	oldDown()
	if err := ep.Send(nil); err != nil {
		t.Fatal(err)
	}
	ep.Deliver(nil)
	if up != 1 || down != 1 {
		t.Fatal("迟到注销清掉新绑定")
	}
	newUp()
	newDown()
	if ep.Send(nil) != ErrNoUplink {
		t.Fatal("自身注销无效")
	}
	ep.Deliver(nil)
	if down != 1 {
		t.Fatal("注销后仍下行")
	}
}
