package containers

import "testing"

func TestContainerFromCgroup(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"cgroup v2 docker scope",
			"0::/system.slice/docker-3f4a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a.scope\n",
			"3f4a9b8c7d6e",
		},
		{
			"cgroup v1 docker path",
			"12:cpu,cpuacct:/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n",
			"abcdef012345",
		},
		{"host process", "0::/system.slice/nginx.service\n", ""},
		{"root cgroup", "0::/\n", ""},
		// A short hex fragment is a unit name, not a container id.
		{"short hex is not a container", "0::/system.slice/docker-abc.scope\n", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := ContainerFromCgroup(c.body); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
