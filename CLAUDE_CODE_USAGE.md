# Utilisation de ssh-mcp avec Claude Code

## Problème résolu

**Avant :** Claude Code ne savait pas qu'il pouvait utiliser `ssh_connect` avec juste un alias, donc il essayait d'utiliser des commandes bash au lieu des outils MCP.

**Maintenant :** `ssh_connect` accepte juste un alias et charge automatiquement les credentials depuis `servers.json` + Windows Credential Manager.

---

## Mode d'emploi pour Claude Code

### 1. Sauvegarder un serveur (une seule fois)

```
Utilise ssh_save_server pour sauvegarder mon VPS :
- alias: vps
- host: 192.168.10.1
- username: sassogba
- password: [ton mot de passe]
- device_type: generic
- auto_connect: true
```

Les credentials sont stockés de manière sécurisée dans Windows Credential Manager, pas dans `servers.json`.

### 2. Se connecter (à chaque session)

**Méthode simple (recommandée) :**
```
Connecte-toi à mon VPS avec ssh_connect(alias='vps')
```

**Méthode complète (pour un nouveau serveur) :**
```
Connecte-toi à 192.168.10.1 avec ssh_connect(alias='vps', host='192.168.10.1', username='sassogba', password='...')
```

### 3. Exécuter des commandes

```
Exécute "df -h" sur vps avec ssh_exec
```

```
Liste les fichiers dans /var/log sur vps avec ssh_list_remote
```

---

## Exemples complets

### Scénario 1 : Premier usage

```
1. Sauvegarde mon serveur Cisco avec ssh_save_server :
   - alias: cisco-core
   - host: 10.0.0.1
   - username: admin
   - password: [password]
   - device_type: cisco
   - auto_connect: true

2. Connecte-toi avec ssh_connect(alias='cisco-core')

3. Fais un backup de la config avec ssh_backup_config(alias='cisco-core', device_type='cisco')
```

### Scénario 2 : Usage quotidien

```
1. Connecte-toi à mon VPS avec ssh_connect(alias='vps')

2. Vérifie l'espace disque avec ssh_exec(alias='vps', command='df -h')

3. Redémarre nginx avec ssh_exec_sudo(alias='vps', command='systemctl restart nginx', sudo_password='...')
```

### Scénario 3 : Équipement réseau

```
1. Connecte-toi au switch MikroTik avec ssh_connect(alias='mikrotik-gw')

2. Affiche les interfaces avec ssh_exec_network(alias='mikrotik-gw', commands=['/interface print'], device_type='mikrotik')

3. Fais un backup avec ssh_backup_config(alias='mikrotik-gw', device_type='mikrotik')
```

---

## Pourquoi ça ne marchait pas avant ?

Claude Code voyait que ssh-mcp était connecté mais :
1. Il ne savait pas qu'il pouvait appeler `ssh_connect` avec juste un alias
2. Il pensait devoir fournir tous les paramètres (host, username, password)
3. Comme il n'avait pas ces infos, il abandonnait et essayait des commandes bash (`claude mcp tools`)

**Solution :** Maintenant `ssh_connect` charge automatiquement depuis `servers.json` quand tu donnes juste l'alias.

---

## Serveurs sauvegardés

Pour voir tes serveurs sauvegardés :
```
Liste mes serveurs SSH avec ssh_list_servers
```

Pour voir les connexions actives :
```
Liste les connexions SSH actives avec ssh_list
```

---

## Auto-connexion au démarrage

Si tu mets `auto_connect: true` lors de la sauvegarde, le serveur se connecte automatiquement au démarrage de ssh-mcp.

Vérifie avec :
```
Liste les connexions SSH actives avec ssh_list
```

---

## Sécurité

- Les mots de passe et passphrases sont stockés dans **Windows Credential Manager**, pas dans `servers.json`
- Host key verification est **strict** par défaut (production-safe)
- Utilise `host_key_policy='auto_add'` uniquement en labo

---

## Dépannage

### "Connexion introuvable"
→ Lance d'abord `ssh_connect(alias='...')` ou vérifie avec `ssh_list_servers`

### "Secret missing in Credential Manager"
→ Le serveur est sauvegardé mais le mot de passe a été supprimé du Credential Manager
→ Re-sauvegarde avec `ssh_save_server` en fournissant le password

### "Host key verification failed"
→ Ajoute la clé hôte à `known_hosts` ou utilise `host_key_policy='auto_add'` (labo uniquement)

### Claude Code n'utilise pas les outils MCP
→ Sois explicite : "Utilise ssh_connect(alias='vps')" au lieu de "connecte-toi au VPS"
