import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title: '송영찬 | 패스키 개인 공간 · ALEPH 08', description: '공개 소개와 패스키로 잠근 나만의 학습 공간. 비공개 내용은 모두 가상 자료입니다.' };
export default function Layout({children}: {children: React.ReactNode}) {return <html lang="ko"><body>{children}</body></html>;}
