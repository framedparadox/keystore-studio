import React, { useState } from "react";
import { ArrowRight, ChevronRight, LifeBuoy, Search } from "lucide-react";
import { HELP_GROUPS, searchHelp, type HelpLink } from "../lib/help";
import { Button, CardHeader, EmptyState } from "./ui";
import { shortcutLabel } from "../lib/platform";
import { IconLegend, searchLegend } from "./IconLegend";

/** Searchable help topics. While a search is typed every match is shown open. */
export const HelpTopics: React.FC<{ onNavigate: (link: HelpLink) => void }> = ({ onNavigate }) => {
  const [query, setQuery] = useState("");
  const searching = query.trim() !== "";
  const groups = searchHelp(query, HELP_GROUPS);
  const legend = searchLegend(query);

  return (
    <div className="space-y-5" data-testid="help-topics">
      <div className="flex flex-col @xl:flex-row @xl:items-start justify-between gap-3">
        <CardHeader title="Help" subtitle="Answers to common questions and a legend of the icons. Keyboard shortcuts have their own tab." icon={LifeBuoy} className="!mb-0" />
        <label className="relative block w-full @xl:w-80 shrink-0">
          <span className="sr-only">Search help</span>
          <Search className="w-4 h-4 text-subtle absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" aria-hidden />
          <input className="field !pl-9" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search help" data-testid="help-search" />
        </label>
      </div>

      {groups.length === 0 && legend.length === 0 ? (
        <EmptyState icon={Search} title="No matching topics" description="Try another word, or look under Keyboard shortcuts." />
      ) : (
        groups.map((g) => (
          <section key={g.id} aria-labelledby={`help-${g.id}`}>
            <h3 id={`help-${g.id}`} className="text-[12px] font-semibold uppercase tracking-wide text-faint mb-2">
              {g.title}
            </h3>
            <div className="rounded-card border border-line divide-y divide-line overflow-hidden bg-surface">
              {g.topics.map((t) => (
                // Keyed on the search state so topics open when a search starts and close again after.
                <details key={`${t.id}:${searching}`} open={searching} className="group" data-testid={`help-topic-${t.id}`}>
                  <summary className="flex items-center gap-2.5 px-4 py-3 cursor-pointer list-none [&::-webkit-details-marker]:hidden hover:bg-surface-2 text-[13px] font-medium text-ink">
                    <ChevronRight className="w-4 h-4 text-subtle shrink-0 transition-transform group-open:rotate-90" aria-hidden />
                    {t.question}
                  </summary>
                  <div className="px-4 pb-4 pl-[42px] space-y-2 text-[13px] text-muted leading-relaxed select-text">
                    {t.answer.map((p, i) => (
                      <p key={i}>{shortcutLabel(p)}</p>
                    ))}
                    {t.link && (
                      <Button size="sm" variant="ghost" className="!px-0 hover:!bg-transparent !text-brand" onClick={() => onNavigate(t.link!)}>
                        {t.link.label} <ArrowRight className="w-3.5 h-3.5" aria-hidden />
                      </Button>
                    )}
                  </div>
                </details>
              ))}
            </div>
          </section>
        ))
      )}
      {legend.length > 0 && <IconLegend groups={legend} />}
    </div>
  );
};
