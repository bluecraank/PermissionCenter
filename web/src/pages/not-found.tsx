import { Link } from 'react-router-dom'

import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/common'

export default function NotFoundPage() {
  return (
    <EmptyState title="Seite nicht gefunden">
      <Button asChild variant="outline" size="sm" className="mt-2">
        <Link to="/">Zum Dashboard</Link>
      </Button>
    </EmptyState>
  )
}
