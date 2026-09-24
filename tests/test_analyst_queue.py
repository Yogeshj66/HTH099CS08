import pytest

from conftest import T0, FakeClock, make_incident
from soc.analyst_queue import AnalystQueue
from soc.incident_manager import InvalidTransition


@pytest.fixture
def q(mgr):
    return AnalystQueue(mgr, capacity=3, clock=FakeClock())


def add(q, mgr, score, **kw):
    inc = make_incident(mgr, severity_score=score, severity="CRITICAL" if score > 75 else "HIGH", **kw)
    q.rebalance()
    return inc["incident_id"]


def statuses(mgr):
    return {i["incident_id"]: i["status"] for i in mgr.list()}


def test_only_capacity_incidents_are_assigned(q, mgr):
    ids = [add(q, mgr, 40 + n * 5) for n in range(10)]
    view = q.view()
    assigned = [i for i in mgr.active() if i["status"] == "ASSIGNED"]
    assert len(assigned) == 3 and view["available"] == 0 and len(view["waiting"]) == 7
    assert len({i["assigned_analyst"] for i in assigned}) == 3               # distinct analysts
    # the three highest-priority incidents hold the analysts
    top = sorted(mgr.active(), key=lambda i: i["priority_rank"])[:3]
    assert {i["incident_id"] for i in top} == {i["incident_id"] for i in assigned}
    assert len(ids) == 10


def test_higher_priority_arrival_takes_slot_from_lower(q, mgr):
    for s in (30, 32, 34):
        add(q, mgr, s)
    big = add(q, mgr, 99)
    st = statuses(mgr)
    assert st[big] == "ASSIGNED" and list(st.values()).count("ASSIGNED") == 3
    assert list(st.values()).count("PENDING") == 1


def test_investigating_is_never_preempted(q, mgr):
    low = add(q, mgr, 30)
    q.acknowledge(low)
    for s in (90, 91, 92, 93):
        add(q, mgr, s)
    st = statuses(mgr)
    assert st[low] == "INVESTIGATING"
    active = [s for s in st.values() if s in ("ASSIGNED", "INVESTIGATING")]
    assert len(active) == 3                                                    # capacity never exceeded


def test_resolve_frees_analyst_and_promotes_waiting(q, mgr):
    ids = [add(q, mgr, 60 + n) for n in range(5)]
    waiting = [i["incident_id"] for i in mgr.active() if i["status"] == "PENDING"]
    victim = next(i["incident_id"] for i in mgr.active() if i["status"] == "ASSIGNED")
    q.resolve(victim)
    now_assigned = [i["incident_id"] for i in mgr.active() if i["status"] == "ASSIGNED"]
    assert len(now_assigned) == 3 and len(set(waiting) & set(now_assigned)) >= 1
    assert mgr.get(victim)["status"] == "RESOLVED" and mgr.get(victim)["assigned_analyst"] is None
    assert len(ids) == 5


def test_false_positive_frees_analyst(q, mgr):
    ids = [add(q, mgr, 50 + n) for n in range(4)]
    assigned = next(i for i in mgr.active() if i["status"] == "ASSIGNED")["incident_id"]
    q.false_positive(assigned)
    assert mgr.get(assigned)["status"] == "FALSE_POSITIVE"
    assert sum(1 for i in mgr.active() if i["status"] == "ASSIGNED") == 3
    assert len(ids) == 4


def test_acknowledge_rules(q, mgr):
    for s in (90, 80, 70, 20):
        add(q, mgr, s)
    waiting = next(i["incident_id"] for i in mgr.active() if i["status"] == "PENDING")
    with pytest.raises(InvalidTransition):
        q.acknowledge(waiting)                                                # no analyst yet
    mine = next(i["incident_id"] for i in mgr.active() if i["status"] == "ASSIGNED")
    assert q.acknowledge(mine)["status"] == "INVESTIGATING"
    with pytest.raises(InvalidTransition):
        q.acknowledge(mine)                                                   # already investigating


def test_closed_incident_cannot_be_reopened(q, mgr):
    i = add(q, mgr, 70)
    q.resolve(i)
    with pytest.raises(InvalidTransition):
        q.resolve(i)
    with pytest.raises(InvalidTransition):
        q.acknowledge(i)


def test_no_available_analysts_all_wait_when_all_pinned(mgr):
    q = AnalystQueue(mgr, capacity=1, clock=FakeClock())
    a = add(q, mgr, 50)
    q.acknowledge(a)
    b = add(q, mgr, 99)
    assert statuses(mgr)[b] == "PENDING" and q.view()["available"] == 0


def test_capacity_change_rebalances(q, mgr):
    for s in (50, 60, 70, 80):
        add(q, mgr, s)
    q.set_capacity(2)
    assert sum(1 for i in mgr.active() if i["status"] == "ASSIGNED") == 2
    q.set_capacity(4)
    assert sum(1 for i in mgr.active() if i["status"] == "ASSIGNED") == 4


def test_view_shape(q, mgr):
    add(q, mgr, 70)
    v = q.view()
    assert v["capacity"] == 3 and len(v["analysts"]) == 3 and v["queue"][0]["rank"] == 1
    assert v["analysts"][0]["incident"]["assigned_analyst"] == "Analyst 1" or v["analysts"][0]["incident"] is None
