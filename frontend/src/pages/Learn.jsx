// pages/Learn.jsx
import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { getLearnArticles, getLearnArticle, getLearnCategories } from '../services/api'
import HashPlayground from '../components/HashPlayground'
import NetworkBackground from '../components/NetworkBackground'
import './Learn.css'

const CATEGORY_LABELS = {
  'kill-chain': 'Kill Chain Fundamentals',
  'cryptography': 'Cryptography & Hashing',
  'malware': 'Malware Types',
  'network': 'Network Attacks',
  'web': 'Web Application Attacks',
  'social-engineering': 'Social Engineering',
}

const DIFFICULTY_COLOR = {
  beginner: '#22c55e',
  intermediate: '#eab308',
  advanced: '#ef4444',
}

function renderContent(text) {
  // Minimal markdown-ish renderer: **bold**, numbered/bulleted lines, paragraphs
  const blocks = text.split('\n\n')
  return blocks.map((block, i) => {
    const html = block
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    if (/^\d+\.\s/.test(block)) {
      return <p key={i} className="ln-list-line" dangerouslySetInnerHTML={{ __html: html }} />
    }
    if (/^-\s/.test(block)) {
      return <p key={i} className="ln-list-line" dangerouslySetInnerHTML={{ __html: html }} />
    }
    return <p key={i} dangerouslySetInnerHTML={{ __html: html }} />
  })
}

export default function Learn() {
  const navigate = useNavigate()
  const { slug } = useParams()

  const [categories, setCategories] = useState([])
  const [articles, setArticles] = useState([])
  const [activeCategory, setActiveCategory] = useState(null)
  const [article, setArticle] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([getLearnCategories(), getLearnArticles()])
      .then(([catRes, artRes]) => {
        setCategories(catRes.data.categories)
        setArticles(artRes.data.articles)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!slug) {
      setArticle(null)
      return
    }
    getLearnArticle(slug).then((res) => setArticle(res.data.article))
  }, [slug])

  const visibleArticles = activeCategory
    ? articles.filter((a) => a.category === activeCategory)
    : articles

  if (loading) {
    return (
      <div className="ln-page">
        <NetworkBackground variant="blue" />
        <p className="ln-loading">Loading Learn hub…</p>
      </div>
    )
  }

  return (
    <div className="ln-page">
      <NetworkBackground variant="blue" />

      <aside className="ln-sidebar">
        <div className="ln-sidebar-title" onClick={() => navigate('/learn')}>Learn</div>
        <button
          className={`ln-cat-btn ${!activeCategory ? 'active' : ''}`}
          onClick={() => setActiveCategory(null)}
        >
          All Topics
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            className={`ln-cat-btn ${activeCategory === cat ? 'active' : ''}`}
            onClick={() => setActiveCategory(cat)}
          >
            {CATEGORY_LABELS[cat] || cat}
          </button>
        ))}
        <button className="ln-back-btn" onClick={() => navigate('/dashboard')}>← Dashboard</button>
      </aside>

      <main className="ln-main">
        {!article && (
          <>
            <h1 className="ln-heading">{activeCategory ? (CATEGORY_LABELS[activeCategory] || activeCategory) : 'All Topics'}</h1>
            <div className="ln-grid">
              {visibleArticles.map((a) => (
                <button key={a.slug} className="ln-card" onClick={() => navigate(`/learn/${a.slug}`)}>
                  <div className="ln-card-top">
                    <span className="ln-diff" style={{ color: DIFFICULTY_COLOR[a.difficulty] }}>{a.difficulty}</span>
                    <span className="ln-read-time">{a.readTime} min read</span>
                  </div>
                  <h3>{a.title}</h3>
                  {a.mitreRefs?.length > 0 && (
                    <div className="ln-mitre-tags">
                      {a.mitreRefs.map((m) => <span key={m} className="ln-mitre-tag">{m}</span>)}
                    </div>
                  )}
                </button>
              ))}
              {visibleArticles.length === 0 && (
                <p className="ln-empty">No articles in this category yet.</p>
              )}
            </div>
          </>
        )}

        {article && (
          <article className="ln-article">
            <button className="ln-article-back" onClick={() => navigate('/learn')}>← All Topics</button>
            <div className="ln-article-meta">
              <span className="ln-diff" style={{ color: DIFFICULTY_COLOR[article.difficulty] }}>{article.difficulty}</span>
              <span className="ln-read-time">{article.readTime} min read</span>
              {article.mitreRefs?.length > 0 && article.mitreRefs.map((m) => (
                <span key={m} className="ln-mitre-tag">{m}</span>
              ))}
            </div>
            <h1>{article.title}</h1>

            <div className="ln-article-body">
              {renderContent(article.content)}
            </div>

            {article.interactive === 'hash-playground' && <HashPlayground />}

            {article.furtherReading?.length > 0 && (
              <div className="ln-further">
                <h4>Further Reading</h4>
                {article.furtherReading.map((f, i) => (
                  <a key={i} href={f.url} target="_blank" rel="noopener noreferrer">{f.label} ↗</a>
                ))}
              </div>
            )}
          </article>
        )}
      </main>
    </div>
  )
}