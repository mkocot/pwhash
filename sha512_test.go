package pwhash

import (
	"reflect"
	"testing"
)

func Test_crypt_sha512(t *testing.T) {
	type args struct {
		salt string
		key  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"1", args{"$6$saltstring", "Hello world!"}, "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu" +
			"esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
		{"2",
			args{"$6$rounds=10000$saltstringsaltstring", "Hello world!"},
			"$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb" +
				"HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
		{"4",
			args{"$6$rounds=5000$toolongsaltstring", "This is just a test"},
			"$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ" +
				"zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"},
		{"5",
			args{"$6$rounds=1400$anotherlongsaltstring",
				"a very much longer text to encrypt.  This one even stretches over more" + "than one line."},
			"$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP" +
				"vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"},
		{"6",
			args{"$6$rounds=77777$short",
				"we have a short salt string but not a short password"},
			"$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g" +
				"ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"},
		{"7",
			args{"$6$rounds=123456$asaltof16chars..", "a short string"},
			"$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc" +
				"elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"},
		{"8",
			args{"$6$rounds=10$roundstoolow", "the minimum number is still observed"},
			"$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x" +
				"hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crypt_sha512([]byte(tt.args.key), []byte(tt.args.salt)); !reflect.DeepEqual(string(got), tt.want) {
				t.Errorf("crypt_sha512() = %v, want %v", string(got), tt.want)
			}
		})
	}
}
