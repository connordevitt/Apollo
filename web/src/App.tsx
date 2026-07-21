import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Landing from './pages/Landing'
import Findings from './pages/Findings'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/findings" element={<Findings />} />
      </Routes>
    </BrowserRouter>
  )
}
