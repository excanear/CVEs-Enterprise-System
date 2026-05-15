"use client";

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import type { RemediationGuidance } from "@/types/api";

interface Props {
  item: RemediationGuidance;
}

export function RemediationItem({ item }: Props) {
  return (
    <div className="rounded-lg border border-border bg-card">
      <Accordion type="single" collapsible>
        <AccordionItem value={item.cluster_id} className="border-0">
          <AccordionTrigger className="px-3 py-2.5 text-left">
            <div className="flex flex-col gap-1 text-left">
              <span className="text-xs font-semibold leading-tight">
                {item.exposure_type.replace(/_/g, " ")}
              </span>
              <span className="text-[10px] font-mono text-muted-foreground truncate max-w-[160px]">
                {item.cluster_id.slice(0, 16)}…
              </span>
            </div>
          </AccordionTrigger>

          <AccordionContent className="px-3 pb-3">
            {item.llm_enriched && (
              <Badge variant="secondary" className="mb-2 text-[9px]">
                AI-enriched
              </Badge>
            )}

            {item.llm_narrative && (
              <p className="mb-2 text-xs text-muted-foreground leading-relaxed">
                {item.llm_narrative}
              </p>
            )}

            <ol className="list-decimal list-inside space-y-1">
              {item.steps.map((step, i) => (
                <li key={i} className="text-xs text-foreground leading-snug">
                  {step}
                </li>
              ))}
            </ol>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  );
}
