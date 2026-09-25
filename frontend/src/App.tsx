import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Upload from './pages/Upload'
import AnalysisProgress from './pages/AnalysisProgress'
import AnalysisResults from './pages/AnalysisResults'
import History from './pages/History'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/analysis/:id/progress" element={<AnalysisProgress />} />
        <Route path="/analysis/:id" element={<AnalysisResults />} />
        <Route path="/history" element={<History />} />
      </Routes>
    </Layout>
  )
}

export default App
