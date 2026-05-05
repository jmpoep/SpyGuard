import { createI18n } from 'vue-i18n'

import de from '@/locales/de.json'
import en from '@/locales/en.json'
import es from '@/locales/es.json'
import fr from '@/locales/fr.json'
import it from '@/locales/it.json'
import pl from '@/locales/pl.json'
import pt from '@/locales/pt.json'
import ru from '@/locales/ru.json'

export default createI18n({
  legacy: true,
  locale: 'en',
  fallbackLocale: 'en',
  messages: {
    de,
    en,
    es,
    fr,
    it,
    pl,
    pt,
    ru,
  },
})
