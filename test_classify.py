"""Ground-truth test using the 15 real repo_owner_changed samples pulled from
the 2026-08-22 snapshot. If a detector change breaks one of these, you want to
know immediately."""
from classify import classify_owner_change

G = "https://github.com/"
CASES = [
    ("com.nursinghomedatabase/mcp", G+"YOUR_GITHUB_USERNAME/nhd-mcp", G+"jmtroller/nhd-mcp", "placeholder_replaced"),
    ("com.useallowance/allowance-mcp", G+"dasmer/allowance-mcp", G+"useallowance/allowance-mcp-public", "converged_to_namespace"),
    ("ai.nefesh/human-state", G+"tomstuhl/nefesh-mcp-server", G+"nefesh-ai/nefesh-mcp-server", "converged_to_namespace"),
    ("ar.com.muovi/mcp-server", G+"muovi-ar/muovi-web", G+"mmiani/mcp-server", "diverged_from_namespace"),
    ("io.github.PedramMadani/legalithm-mcp-server", G+"PedramMadani/legalithm-cli", G+"legalithm-org/legalithm", "diverged_from_namespace"),
    ("io.github.Dewars30/fulcrum", G+"Dewars30/fulcrum-io", G+"Fulcrum-Governance/fulcrum-io", "diverged_from_namespace"),
    ("com.storydoc/mcp", G+"VladZh97/mcp", G+"DoTell-org/mcp", "unrelated"),
    ("com.compoid/mcp-server", "https://gitlab.com/compoid-ai/compoid-mcp.git", G+"compoid/compoid-mcp.git", "forge_changed"),
    ("io.github.AIweather-Anurag/ottasia", G+"Alweather-Anurag/ottasia", G+"AIweather-Anurag/ottasia-mcp-server", "homoglyph_confusable"),
    ("com.healthai/radar", G+"thehealthai/fda-risk-radar-mcp", G+"healthai-hq/fda-risk-radar", "both_match_namespace"),
    ("io.github.hshintelligence/data-on-demand", G+"hshintelligence/data-on-demand", G+"HSH-Intelligence/data-on-demand", "case_or_punctuation_only"),
    ("ai.trendsmcp/youtube", G+"trendsmcp/youtube-trends-mcp", G+"trendsmcp-ai/youtube-trends-mcp", "both_match_namespace"),
    ("io.github.Pattyboi101/indiestack", G+"indiestack/indiestack", G+"Pattyboi101/indiestack", "converged_to_namespace"),
    ("ai.trendsmcp/amazon", G+"trendsmcp/amazon-trends-mcp", G+"trendsmcp-ai/amazon-trends-mcp", "both_match_namespace"),
    ("com.agishub/chronosync-mcp", G+"jmavid/chronosync-mcp", G+"agishub/chronosync-mcp", "converged_to_namespace"),
]

fails = 0
for name, a, b, want in CASES:
    got, note = classify_owner_change(name, a, b)
    ok = got == want
    fails += not ok
    print("%s %-28s %-26s %s" % ("PASS" if ok else "FAIL", got, name[:26], note))
    if not ok:
        print("       expected: %s" % want)
print("\n%d/%d pass" % (len(CASES) - fails, len(CASES)))