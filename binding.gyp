{
  'target_defaults': {
    'variables': {
      'version': '<!(node -pe \'require("./package.json").version\')'
    },
    'defines': [
      'VERSION="<@(version)"'
    ]
  },

  'targets': [
    {
      'target_name': 'x509',
      'sources': [
        'src/addon.cc',
        'src/x509.cc'
      ],
      'include_dirs': [
        'include'
      ]
    }
  ]
}
