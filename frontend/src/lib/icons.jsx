// Minimal inline icon set (no icon dependency).
const I = (p) => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor"
       strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...p.svg}>
    {p.children}
  </svg>
);

export const IconShield = (s) => <I svg={s}><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" /></I>;
export const IconUpload = (s) => <I svg={s}><path d="M12 15V4M8 8l4-4 4 4M5 20h14" /></I>;
export const IconGrid = (s) => <I svg={s}><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></I>;
export const IconFlag = (s) => <I svg={s}><path d="M5 21V4M5 4h11l-2 4 2 4H5" /></I>;
export const IconList = (s) => <I svg={s}><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" /></I>;
export const IconMap = (s) => <I svg={s}><path d="M9 4L3 6v14l6-2 6 2 6-2V4l-6 2-6-2zM9 4v14M15 6v14" /></I>;
export const IconMatrix = (s) => <I svg={s}><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M3 9h18M3 15h18M9 3v18M15 3v18" /></I>;
export const IconCode = (s) => <I svg={s}><path d="M16 18l6-6-6-6M8 6l-6 6 6 6" /></I>;
export const IconClose = (s) => <I svg={s}><path d="M18 6L6 18M6 6l12 12" /></I>;
export const IconExternal = (s) => <I svg={s}><path d="M15 3h6v6M10 14L21 3M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" /></I>;
export const IconChevron = (s) => <I svg={s}><path d="M9 6l6 6-6 6" /></I>;
export const IconAlert = (s) => <I svg={s}><path d="M12 9v4M12 17h.01M10.3 3.9L2 18a2 2 0 001.7 3h16.6a2 2 0 001.7-3L14 3.9a2 2 0 00-3.4 0z" /></I>;
