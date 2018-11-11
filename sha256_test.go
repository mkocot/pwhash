package pwhash

import (
	"reflect"
	"testing"
)

func Test_crypt_sha256(t *testing.T) {
	type args struct {
		salt string
		key  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"1", args{"$5$saltstring", "Hello world!"},
			"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"},
		{"2", args{"$5$rounds=10000$saltstringsaltstring", "Hello world!"},
			"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"},
		{"3", args{"$5$rounds=5000$toolongsaltstring", "This is just a test"},
			"$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5"},
		{"4", args{"$5$rounds=1400$anotherlongsaltstring",
			"a very much longer text to encrypt.  This one even stretches over morethan one line."},
			"$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1"},
		{"5", args{"$5$rounds=77777$short", "we have a short salt string but not a short password"},
			"$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"},
		{"6", args{"$5$rounds=123456$asaltof16chars..", "a short string"},
			"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD"},
		{"7", args{"$5$rounds=10$roundstoolow", "the minimum number is still observed"},
			"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cryptSha256([]byte(tt.args.key), []byte(tt.args.salt)); !reflect.DeepEqual(string(got), tt.want) {
				t.Errorf("crypt_sha256() = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}
