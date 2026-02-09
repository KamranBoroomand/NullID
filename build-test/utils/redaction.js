const severityRank = { low: 1, medium: 2, high: 3 };
export function resolveOverlaps(matches) {
    if (matches.length === 0)
        return [];
    const byStart = [...matches].sort((a, b) => a.start - b.start);
    const resolved = [];
    let i = 0;
    while (i < byStart.length) {
        const group = [byStart[i]];
        let windowEnd = byStart[i].end;
        let j = i + 1;
        while (j < byStart.length && byStart[j].start < windowEnd) {
            group.push(byStart[j]);
            windowEnd = Math.max(windowEnd, byStart[j].end);
            j += 1;
        }
        const best = [...group].sort((a, b) => {
            const lenDiff = b.end - b.start - (a.end - a.start);
            if (lenDiff !== 0)
                return lenDiff;
            const sevDiff = severityRank[b.severity] - severityRank[a.severity];
            if (sevDiff !== 0)
                return sevDiff;
            return a.start - b.start;
        })[0];
        resolved.push(best);
        i = j;
    }
    return resolved.sort((a, b) => a.start - b.start);
}
