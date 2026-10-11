// components/blue/guide/guideContext.js
// Shared guide settings and the "What is this?" opener, provided by the page.
import { createContext, useContext } from 'react'

const NOOP = () => {}
export const GuideContext = createContext({
  guided: true, advanced: false, openTerm: NOOP, seen: {}, markSeen: NOOP,
})
export const useGuide = () => useContext(GuideContext)
