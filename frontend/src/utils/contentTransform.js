import React from 'react';

export const urlRegex = /(https?:\/\/[^\s]+)/g;
export const imageExtRegex = /\.(jpg|jpeg|png|gif|webp)$/i;

export const transformContent = (text) => {
  if (!text) return text;
  
  const parts = text.split(urlRegex);
  return parts.map((part, i) => {
    if (part.match(urlRegex)) {
      if (part.match(imageExtRegex)) {
        return (
          <a 
            key={i} 
            href={part} 
            target="_blank" 
            rel="noopener noreferrer"
            style={{ display: 'block', maxWidth: '100%' }}
          >
            <img 
              src={part} 
              alt="Content" 
              style={{ maxWidth: '100%', height: 'auto' }}
              onError={(e) => {
                e.target.style.display = 'none';
                e.target.parentElement.innerHTML = part;
              }}
            />
          </a>
        );
      }
      return (
        <a 
          key={i} 
          href={part} 
          target="_blank" 
          rel="noopener noreferrer"
        >
          {part}
        </a>
      );
    }
    return part;
  });
};
