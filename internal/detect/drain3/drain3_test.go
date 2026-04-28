package drain3

import "testing"

func TestRepeatedLineMergesIntoOneCluster(t *testing.T) {
	m := New()
	for i := 0; i < 10; i++ {
		m.Add("GET /api/users 200 12ms")
	}
	if got := len(m.Clusters()); got != 1 {
		t.Fatalf("want 1 cluster, got %d", got)
	}
	if size := m.Clusters()[0].Size; size != 10 {
		t.Errorf("want size 10, got %d", size)
	}
}

func TestDifferentTokenCountsCreateDifferentClusters(t *testing.T) {
	m := New()
	m.Add("GET /api/users 200")
	m.Add("POST /api/users/123 created successfully")
	if got := len(m.Clusters()); got != 2 {
		t.Fatalf("want 2 clusters, got %d", got)
	}
}

func TestVaryingNumbersCollapseToWildcard(t *testing.T) {
	m := New()
	m.Add("request id=42 took 12ms")
	m.Add("request id=99 took 8ms")
	m.Add("request id=100 took 1500ms")
	if got := len(m.Clusters()); got != 1 {
		t.Fatalf("want 1 cluster (numeric tokens should mask), got %d", got)
	}
}

func TestDistinctErrorsStayDistinct(t *testing.T) {
	m := New()
	m.Add("connection refused redis-master")
	m.Add("permission denied user=root")
	if got := len(m.Clusters()); got != 2 {
		t.Fatalf("want 2 clusters for distinct errors, got %d", got)
	}
}

func TestNewClusterFlagFiresOnceThenFalse(t *testing.T) {
	m := New()
	_, isNew := m.Add("first line ever seen")
	if !isNew {
		t.Fatal("first call should report isNew=true")
	}
	_, isNew = m.Add("first line ever seen")
	if isNew {
		t.Error("second matching call should report isNew=false")
	}
}
