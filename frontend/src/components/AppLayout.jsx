import { AppBar, Box, Button, Container, Link, Toolbar, Typography } from '@mui/material'
import { NavLink } from 'react-router-dom'

const skipLinkSx = {
  position: 'absolute',
  left: 8,
  top: -48,
  zIndex: 'tooltip',
  p: 1,
  bgcolor: 'background.paper',
  color: 'primary.main',
  '&:focus': { top: 8 },
}

const navLinkSx = {
  '&.active': { textDecoration: 'underline', textUnderlineOffset: 4 },
  // The theme's dark outline is hard to see on the blue header.
  '&.Mui-focusVisible': { outlineColor: 'currentColor' },
}

export default function AppLayout({ children }) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <Link href="#main-content" sx={skipLinkSx}>
        Skip to main content
      </Link>
      <AppBar position="static" component="header">
        <Toolbar sx={{ gap: 2, flexWrap: 'wrap' }}>
          <Typography component="p" variant="h3" sx={{ flexGrow: 1 }}>
            Phishing URL Checker
          </Typography>
          <Box component="nav" aria-label="Main">
            <Button color="inherit" component={NavLink} to="/" end sx={navLinkSx}>
              Check a URL
            </Button>
            <Button color="inherit" component={NavLink} to="/session" sx={navLinkSx}>
              This session
            </Button>
          </Box>
        </Toolbar>
      </AppBar>
      <Container
        component="main"
        id="main-content"
        tabIndex={-1}
        maxWidth="md"
        sx={{ flexGrow: 1, py: 4, outline: 'none' }}
      >
        {children}
      </Container>
      <Box component="footer" sx={{ borderTop: 1, borderColor: 'divider' }}>
        <Container maxWidth="md" sx={{ py: 2 }}>
          <Typography variant="body2" color="text.secondary">
            Analysis uses the URL text only. No page is opened.
          </Typography>
        </Container>
      </Box>
    </Box>
  )
}
