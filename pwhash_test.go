package pwhash

import (
	"testing"
)

var (
	password1     = "password"
	password2     = "assword"
	hashWithSalt1 = "$1$sRN7MKRJ$XfbAXBpoOphTIhBRZuPAl."
	hashWithSalt2 = "$1$sRN7MKRJ$XfbAXBpoOphTIhBRZuAPl."
)

func Test1(t *testing.T) {
	isOk, err := Verify(password1, hashWithSalt1)
	if err != nil && isOk {
		t.Fail()
	}
	if !isOk {
		t.Fatal(err)
	}
}

func Test2(t *testing.T) {
	isOk, err := Verify(password1, hashWithSalt2)
	if err != nil && isOk {
		t.Fail()
	}
	if isOk {
		t.Fail()
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		password     string
		hashWithSalt string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"md5", args{"password", "$1$sRN7MKRJ$XfbAXBpoOphTIhBRZuPAl."}, true, false},
		{"sha256", args{"Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"}, true, false},
		{"sha256", args{"Hello world!", "$5$differents$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"}, false, false},
		{"sha512", args{"Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu" +
			"esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.args.password, tt.args.hashWithSalt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
