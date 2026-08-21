# Configuration ssh-mcp pour Claude Code

## Installation

### 1. Ajouter ssh-mcp à la configuration Claude Code

Édite ton fichier de configuration Claude Code (généralement `~/.config/claude/config.json` ou via les settings de l'app) :

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "python",
      "args": ["D:\\Steph\\script\\ssh-mcp\\server.py"],
      "env": {},
      "disabled": false
    }
  }
}
```

### 2. Redémarre Claude Code

Ferme et rouvre Claude Code pour que le serveur MCP soit chargé.

### 3. Vérifie que ssh-mcp est connecté

Dans Claude Code, tape :
```
Liste les serveurs MCP disponibles
```

Tu devrais voir `ssh-mcp` dans la liste.

---

## Utilisation

### Première connexion (sauvegarder le serveur)

```
Utilise ssh_save_server pour sauvegarder mon VPS :
- alias: vps
- host: 192.168.10.1
- username: sassogba
- password: [ton mot de passe]
- auto_connect: true
```

### Connexions suivantes (mode rapide)

```
Connecte-toi à mon VPS avec ssh_connect(alias='vps')
```

### Exécuter des commandes

```
Exécute "df -h" sur vps avec ssh_exec
```

```
Exécute "systemctl restart nginx" avec sudo sur vps
```

```
Liste les fichiers dans /var/log sur vps
```

---

## Exemples complets

### Scénario 1 : Gestion d'un serveur Linux

```
1. Sauvegarde mon serveur :
   ssh_save_server(alias='vps', host='192.168.10.1', username='sassogba', password='...', auto_connect=true)

2. Connecte-toi :
   ssh_connect(alias='vps')

3. Vérifie l'espace disque :
   ssh_exec(alias='vps', command='df -h')

4. Vérifie les services :
   ssh_exec(alias='vps', command='systemctl status nginx')

5. Redémarre nginx avec sudo :
   ssh_exec_sudo(alias='vps', command='systemctl restart nginx', sudo_password='...')
```

### Scénario 2 : Backup d'un switch Cisco

```
1. Sauvegarde le switch :
   ssh_save_server(alias='cisco-core', host='10.0.0.1', username='admin', password='...', device_type='cisco', auto_connect=true)

2. Connecte-toi :
   ssh_connect(alias='cisco-core')

3. Fais un backup :
   ssh_backup_config(alias='cisco-core', device_type='cisco')

4. Vérifie les interfaces :
   ssh_exec_network(alias='cisco-core', commands=['show ip interface brief'], device_type='cisco')
```

### Scénario 3 : Tunnel SSH vers une base de données

```
1. Connecte-toi au serveur :
   ssh_connect(alias='vps')

2. Crée un tunnel vers MySQL :
   ssh_tunnel(alias='vps', label='mysql', local_port=3307, remote_host='localhost', remote_port=3306)

3. Maintenant tu peux te connecter à MySQL sur localhost:3307

4. Ferme le tunnel quand tu as fini :
   ssh_close_tunnel(alias='vps', label='mysql')
```

---

## Dépannage

### Claude Code n'utilise pas ssh-mcp

**Symptôme :** Claude Code essaie d'utiliser des commandes bash (`claude mcp tools`) au lieu d'appeler les outils MCP.

**Solution :** Sois très explicite dans ta demande :

❌ **Mauvais :**
```
Connecte-toi à mon VPS 192.168.10.1
```

✅ **Bon :**
```
Utilise ssh_connect pour te connecter à mon VPS avec l'alias 'vps'
```

ou encore mieux :

✅ **Meilleur :**
```
Connecte-toi avec ssh_connect(alias='vps')
```

### "Connexion introuvable"

**Cause :** Tu n'as pas encore appelé `ssh_connect`.

**Solution :**
```
Connecte-toi d'abord avec ssh_connect(alias='vps')
```

### "Secret missing in Credential Manager"

**Cause :** Le serveur est sauvegardé mais le mot de passe a été supprimé du Windows Credential Manager.

**Solution :**
```
Re-sauvegarde le serveur avec ssh_save_server en fournissant le password
```

### ssh-mcp ne démarre pas

**Vérifications :**

1. Python est installé et dans le PATH :
   ```bash
   python --version
   ```

2. Les dépendances sont installées :
   ```bash
   pip install -r D:\Steph\script\ssh-mcp\requirements.txt
   ```

3. Le chemin dans la config est correct :
   ```json
   "args": ["D:\\Steph\\script\\ssh-mcp\\server.py"]
   ```
   Note les doubles backslashes `\\` en JSON.

4. Vérifie les logs de Claude Code pour voir les erreurs de démarrage.

---

## Commandes utiles

### Lister les serveurs sauvegardés
```
Liste mes serveurs SSH avec ssh_list_servers
```

### Lister les connexions actives
```
Liste les connexions SSH actives avec ssh_list
```

### Déconnecter
```
Déconnecte-toi de vps avec ssh_disconnect(alias='vps')
```

### Supprimer un serveur sauvegardé
```
Supprime le serveur 'old-server' avec ssh_remove_server(alias='old-server')
```

---

## Sécurité

- Les mots de passe sont stockés dans **Windows Credential Manager**, pas dans des fichiers
- Host key verification est **strict** par défaut (production-safe)
- Les connexions sont persistantes mais isolées (thread-safe)
- Rate limiting automatique pour protéger les équipements réseau

---

## Support

- Documentation complète : `README.md`
- Guide d'utilisation : `CLAUDE_CODE_USAGE.md`
- Changelog : `CHANGELOG.md`
- Issues : Contacte Stéphane A.
