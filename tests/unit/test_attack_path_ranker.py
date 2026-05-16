"""Unit tests — AttackPathRanker composite scoring formula."""
from __future__ import annotations

import pytest

from ai_correlation.application.algorithms.attack_path_ranker import (
    AttackPathRanker,
    _W_CONFIDENCE,
    _W_HOPS,
    _W_POC,
    _W_PROPAGATION,
    _W_DEP_CVSS,
)
from ai_correlation.domain.value_objects.ranked_attack_path import RankedAttackPath


def _make_path(**overrides) -> dict:
    base = {
        "source_endpoint_id": "ep-001",
        "target_asset_id": "asset-001",
        "hops": 2,
        "confidence": 0.8,
        "poc_triggered": False,
        "dep_cvss": 0.0,
        "risk_score": 0.5,
        "path_node_ids": ["n1", "n2", "n3"],
    }
    base.update(overrides)
    return base


class TestAttackPathRankerWeights:
    def test_weights_sum_to_one(self):
        total = _W_CONFIDENCE + _W_HOPS + _W_POC + _W_PROPAGATION + _W_DEP_CVSS
        assert total == pytest.approx(1.0)


class TestAttackPathRankerScoring:
    def test_single_path_returns_rank_1(self):
        ranker = AttackPathRanker()
        paths = [_make_path()]
        result = ranker.rank(paths, tenant_id="t1")
        assert len(result) == 1
        assert result[0].rank == 1

    def test_empty_paths_returns_empty(self):
        ranker = AttackPathRanker()
        result = ranker.rank([], tenant_id="t1")
        assert result == []

    def test_composite_score_bounded_0_to_1(self):
        ranker = AttackPathRanker()
        paths = [
            _make_path(confidence=1.0, hops=1, poc_triggered=True, dep_cvss=10.0),
            _make_path(confidence=0.0, hops=100, poc_triggered=False, dep_cvss=0.0),
        ]
        result = ranker.rank(paths, tenant_id="t1")
        for r in result:
            assert 0.0 <= r.composite_score <= 1.0

    def test_poc_triggered_increases_score(self):
        ranker = AttackPathRanker()
        without_poc = ranker.rank([_make_path(poc_triggered=False)], tenant_id="t1")[0]
        with_poc = ranker.rank([_make_path(poc_triggered=True)], tenant_id="t1")[0]
        assert with_poc.composite_score > without_poc.composite_score

    def test_higher_confidence_increases_score(self):
        ranker = AttackPathRanker()
        low_conf = ranker.rank([_make_path(confidence=0.2)], tenant_id="t1")[0]
        high_conf = ranker.rank([_make_path(confidence=0.9)], tenant_id="t1")[0]
        assert high_conf.composite_score > low_conf.composite_score

    def test_fewer_hops_increases_score(self):
        ranker = AttackPathRanker()
        many_hops = ranker.rank([_make_path(hops=10)], tenant_id="t1")[0]
        few_hops = ranker.rank([_make_path(hops=1)], tenant_id="t1")[0]
        assert few_hops.composite_score > many_hops.composite_score

    def test_higher_dep_cvss_increases_score(self):
        ranker = AttackPathRanker()
        no_cvss = ranker.rank([_make_path(dep_cvss=0.0)], tenant_id="t1")[0]
        high_cvss = ranker.rank([_make_path(dep_cvss=9.8)], tenant_id="t1")[0]
        assert high_cvss.composite_score > no_cvss.composite_score

    def test_deeper_propagation_increases_score(self):
        ranker = AttackPathRanker()
        ep_id = "ep-test"
        shallow = ranker.rank(
            [_make_path(source_endpoint_id=ep_id)],
            tenant_id="t1",
            propagation_by_endpoint={ep_id: 1},
            max_propagation=5,
        )[0]
        deep = ranker.rank(
            [_make_path(source_endpoint_id=ep_id)],
            tenant_id="t1",
            propagation_by_endpoint={ep_id: 5},
            max_propagation=5,
        )[0]
        assert deep.composite_score > shallow.composite_score

    def test_ranking_order_descending(self):
        ranker = AttackPathRanker()
        paths = [
            _make_path(source_endpoint_id="ep1", confidence=0.3, poc_triggered=False),
            _make_path(source_endpoint_id="ep2", confidence=0.9, poc_triggered=True),
            _make_path(source_endpoint_id="ep3", confidence=0.6, poc_triggered=False),
        ]
        result = ranker.rank(paths, tenant_id="t1")
        assert result[0].rank == 1
        assert result[0].composite_score >= result[1].composite_score >= result[2].composite_score

    def test_score_components_match_formula(self):
        ranker = AttackPathRanker()
        path = _make_path(
            confidence=0.8,
            hops=2,
            poc_triggered=False,
            dep_cvss=5.0,
            source_endpoint_id="ep1",
        )
        result = ranker.rank(
            [path],
            tenant_id="t1",
            propagation_by_endpoint={"ep1": 3},
            max_propagation=10,
        )[0]
        expected_conf = 0.8 * _W_CONFIDENCE
        expected_hops = (1.0 / 2) * _W_HOPS
        expected_poc = 0.0 * _W_POC
        expected_prop = (3.0 / 10.0) * _W_PROPAGATION
        expected_cvss = (5.0 / 10.0) * _W_DEP_CVSS
        expected = expected_conf + expected_hops + expected_poc + expected_prop + expected_cvss
        assert result.composite_score == pytest.approx(expected, abs=1e-9)


class TestAttackPathRankerResultFields:
    def test_result_has_correct_tenant_id(self):
        ranker = AttackPathRanker()
        result = ranker.rank([_make_path()], tenant_id="acme-corp")
        assert result[0].tenant_id == "acme-corp"

    def test_result_preserves_source_and_target(self):
        ranker = AttackPathRanker()
        path = _make_path(source_endpoint_id="src-99", target_asset_id="tgt-99")
        result = ranker.rank([path], tenant_id="t1")
        assert result[0].source_endpoint_id == "src-99"
        assert result[0].target_asset_id == "tgt-99"

    def test_hops_zero_defaults_to_one(self):
        """hops=0 should be treated as 1 to avoid division by zero."""
        ranker = AttackPathRanker()
        path = _make_path(hops=0)
        result = ranker.rank([path], tenant_id="t1")
        assert result[0].hops == 1
